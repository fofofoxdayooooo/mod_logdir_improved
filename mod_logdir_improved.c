/*
 * mod_logdir_improved.c - A more flexible Apache module for dynamic log directories
 *
 * This version enhances the original mod_logdir to support dynamic log paths
 * based on per-request information, such as authenticated user IDs.
 *
 * It introduces a new directive `LogFileFormat` which works similar to
 * `LogFormat` but defines a dynamic log file path instead.
 *
 * This version supports both Linux and FreeBSD systems.
 *
 * NOTE: LogFileFormat directive requires Apache 2.4 or later.
 * On Apache 2.2, only the LogDirPath directive is effective.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_errno.h"
#include "apr_hash.h"
#include "apr_thread_mutex.h"
#include "http_request.h"
#include "apr_time.h"
#include "apr_lib.h"
#include "ap_expr.h"
#include "ap_provider.h"
#include "mod_log_config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <string.h>

#ifndef APLOG_USE_MODULE
#define APLOG_USE_MODULE logdir_improved
#endif

module AP_MODULE_DECLARE_DATA logdir_improved_module;

/* -----------------------------------------
   FD garbage collection structure
----------------------------------------- */
typedef struct {
    apr_file_t *file;
    apr_time_t last_access;
} logger_entry;

/* -----------------------------------------
   Per-server configuration
----------------------------------------- */
typedef struct {
    const char *logdir_path;
    const char *logdir_user;
    const char *logdir_group;
    uid_t uid;
    gid_t gid;
    const char *log_file_format;
    ap_expr_info_t *log_file_expr;
    const char *log_entry_format;
    apr_hash_t *loggers; /* Stores logger_entry for each dynamic path */
    int max_loggers; /* For FD garbage collection */
    apr_thread_mutex_t *logger_mutex; /* Protects access to loggers hash table */
    apr_pool_t *logger_pool; /* Dedicated sub-pool for logger_entry allocation */
    int gc_interval; /* Garbage collection interval in seconds */
    int requests_before_gc; /* Number of requests before running GC */
    int disable_standard_log; /* Flag to disable standard logging */
} logdir_config;

/* -----------------------------------------
   Static functions (forward declarations)
----------------------------------------- */
static apr_status_t create_secure_logdir(server_rec *s, const char *path, uid_t uid, gid_t gid);
static int logdir_log_transaction(request_rec *r);
static int logdir_child_init(apr_pool_t *p, server_rec *s);

/* -----------------------------------------
   Configuration creation and merging
----------------------------------------- */
static void *create_logdir_config(apr_pool_t *p, server_rec *s) {
    logdir_config *conf = apr_pcalloc(p, sizeof(*conf));
    conf->logdir_path  = NULL;
    conf->logdir_user  = NULL;
    conf->logdir_group = NULL;
    conf->uid = (uid_t)-1;
    conf->gid = (gid_t)-1;
    conf->log_file_format = NULL;
    conf->log_file_expr = NULL;
    conf->log_entry_format = "%h %l %u %t \"%r\" %>s %b"; // Default Common Log Format
    
    // Create a dedicated sub-pool for logger entries to ensure clean shutdown
    apr_pool_create(&conf->logger_pool, p);
    conf->loggers = apr_hash_make(conf->logger_pool);
    
    conf->max_loggers = 100; // Simple limit
    conf->gc_interval = 300; // Default 5 minutes
    conf->requests_before_gc = 100; // Default 100 requests
    conf->disable_standard_log = 0;
    apr_thread_mutex_create(&conf->logger_mutex, APR_THREAD_MUTEX_DEFAULT, p);
    return conf;
}

static void *merge_logdir_config(apr_pool_t *p, void *basev, void *addv) {
    logdir_config *base = (logdir_config*)basev;
    logdir_config *add  = (logdir_config*)addv;
    logdir_config *conf = apr_pcalloc(p, sizeof(*conf));
    conf->logdir_path      = add->logdir_path ? add->logdir_path : base->logdir_path;
    conf->logdir_user      = add->logdir_user ? add->logdir_user : base->logdir_user;
    conf->logdir_group     = add->logdir_group ? add->logdir_group : base->logdir_group;
    conf->uid              = (add->uid != (uid_t)-1) ? add->uid : base->uid;
    conf->gid              = (add->gid != (gid_t)-1) ? add->gid : base->gid;
    conf->log_file_format  = add->log_file_format ? add->log_file_format : base->log_file_format;
    conf->log_file_expr    = add->log_file_expr ? add->log_file_expr : base->log_file_expr;
    conf->log_entry_format = add->log_entry_format ? add->log_entry_format : base->log_entry_format;
    conf->disable_standard_log = add->disable_standard_log || base->disable_standard_log;
    
    // Create a new dedicated sub-pool for the merged config
    apr_pool_create(&conf->logger_pool, p);
    conf->loggers          = apr_hash_make(conf->logger_pool);
    
    conf->max_loggers      = add->max_loggers;
    conf->gc_interval      = add->gc_interval;
    conf->requests_before_gc = add->requests_before_gc;
    apr_thread_mutex_create(&conf->logger_mutex, APR_THREAD_MUTEX_DEFAULT, p);
    return conf;
}

/* -----------------------------------------
   Directive handlers
----------------------------------------- */
static const char *set_logdir_path(cmd_parms *cmd, void *dummy, const char *arg) {
    logdir_config *conf = ap_get_module_config(cmd->server->module_config, &logdir_improved_module);
    conf->logdir_path = arg;
    return NULL;
}

static const char *set_logdir_user(cmd_parms *cmd, void *dummy, const char *arg) {
    struct passwd *pw = getpwnam(arg);
    if (!pw) {
        return apr_pstrcat(cmd->pool, "Invalid user for LogDirUser: ", arg, NULL);
    }
    logdir_config *conf = ap_get_module_config(cmd->server->module_config, &logdir_improved_module);
    conf->logdir_user = arg;
    conf->uid = pw->pw_uid;
    return NULL;
}

static const char *set_logdir_group(cmd_parms *cmd, void *dummy, const char *arg) {
    struct group *gr = getgrnam(arg);
    if (!gr) {
        return apr_pstrcat(cmd->pool, "Invalid group for LogDirGroup: ", arg, NULL);
    }
    logdir_config *conf = ap_get_module_config(cmd->server->module_config, &logdir_improved_module);
    conf->logdir_group = arg;
    conf->gid = gr->gr_gid;
    return NULL;
}

static const char *set_log_file_format(cmd_parms *cmd, void *dummy, const char *arg) {
    logdir_config *conf = ap_get_module_config(cmd->server->module_config, &logdir_improved_module);
    conf->log_file_format = arg;
    
    ap_expr_info_t *expr = ap_expr_parse_cmd(cmd, arg, AP_EXPR_FLAG_STRING_RESULT, NULL);
    if (ap_expr_parse_error(cmd, expr)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, cmd->server,
                     "mod_logdir_improved: Could not parse LogFileFormat expression. Falling back to LogDirPath.");
        conf->log_file_expr = NULL;
        return NULL;
    }
    conf->log_file_expr = expr;
    return NULL;
}

static const char *set_log_entry_format(cmd_parms *cmd, void *dummy, const char *arg) {
    logdir_config *conf = ap_get_module_config(cmd->server->module_config, &logdir_improved_module);
    conf->log_entry_format = arg;
    return NULL;
}

static const char *set_log_gc_interval(cmd_parms *cmd, void *dummy, const char *arg) {
    logdir_config *conf = ap_get_module_config(cmd->server->module_config, &logdir_improved_module);
    conf->gc_interval = atoi(arg);
    if (conf->gc_interval <= 0) {
        return "LogDirGCInterval must be a positive integer.";
    }
    return NULL;
}

static const char *set_requests_before_gc(cmd_parms *cmd, void *dummy, const char *arg) {
    logdir_config *conf = ap_get_module_config(cmd->server->module_config, &logdir_improved_module);
    conf->requests_before_gc = atoi(arg);
    if (conf->requests_before_gc <= 0) {
        return "LogDirRequestsBeforeGC must be a positive integer.";
    }
    return NULL;
}

static const char *set_disable_standard_log(cmd_parms *cmd, void *dummy, int arg) {
    logdir_config *conf = ap_get_module_config(cmd->server->module_config, &logdir_improved_module);
    conf->disable_standard_log = arg;
    return NULL;
}

/* -----------------------------------------
   FD garbage collection
----------------------------------------- */
static void close_stale_loggers(logdir_config *conf, apr_pool_t *p) {
    apr_hash_index_t *hi;
    logger_entry *entry;
    apr_hash_t *keys_to_remove = apr_hash_make(p);
    
    apr_time_t now = apr_time_now();
    for (hi = apr_hash_first(p, conf->loggers); hi; hi = apr_hash_next(hi)) {
        const void *key;
        apr_hash_this(hi, &key, NULL, (void**)&entry);
        if ((now - entry->last_access) > (conf->gc_interval * APR_USEC_PER_SEC)) {
            apr_hash_set(keys_to_remove, key, APR_HASH_KEY_STRING, apr_pstrdup(p, key));
        }
    }
    
    while (apr_hash_count(conf->loggers) >= conf->max_loggers) {
        const char *oldest_key = NULL;
        apr_time_t oldest_time = apr_time_now();
        
        for (hi = apr_hash_first(p, conf->loggers); hi; hi = apr_hash_next(hi)) {
            const void *key;
            apr_hash_this(hi, &key, NULL, (void**)&entry);
            if (entry->last_access < oldest_time) {
                oldest_time = entry->last_access;
                oldest_key = key;
            }
        }
        if (oldest_key) {
            apr_hash_set(keys_to_remove, oldest_key, APR_HASH_KEY_STRING, apr_pstrdup(p, oldest_key));
        } else {
            break;
        }
    }

    const void *key_to_remove;
    for (hi = apr_hash_first(p, keys_to_remove); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, &key_to_remove, NULL, NULL);
        entry = apr_hash_get(conf->loggers, key_to_remove, APR_HASH_KEY_STRING);
        if (entry) {
            apr_file_close(entry->file);
            apr_hash_set(conf->loggers, key_to_remove, APR_HASH_KEY_STRING, NULL);
        }
    }
}

/* -----------------------------------------
   Directory and File Handling
----------------------------------------- */
static apr_status_t create_secure_logdir(server_rec *s, const char *path, uid_t uid, gid_t gid) {
    struct stat st;
    apr_status_t rv = APR_SUCCESS;
    char errbuf[256];

    if (mkdir(path, 0700) == -1) {
        if (errno != EEXIST) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                         "mod_logdir_improved: Failed to mkdir %s: %s", path, strerror(errno));
            return APR_EGENERAL;
        }
    }
    
    // Re-check after mkdir to handle race conditions and verify existence
    if (lstat(path, &st) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                     "mod_logdir_improved: lstat failed to confirm directory creation for %s: %s", path, strerror(errno));
        return APR_EGENERAL;
    }
    
    if (!S_ISDIR(st.st_mode)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_logdir_improved: %s exists but is not a directory", path);
        return APR_EGENERAL;
    }

    if (uid != (uid_t)-1 && (st.st_uid != uid || st.st_gid != gid)) {
        // Correct ownership if it's wrong
        if (chown(path, uid, gid) == -1) {
             ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                     "mod_logdir_improved: Existing directory %s has wrong ownership, failed to chown: %s", path, strerror(errno));
            rv = APR_EGENERAL;
        } else {
             ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                          "mod_logdir_improved: Corrected ownership for existing logdir %s", path);
        }
    }
    return rv;
}

/* -----------------------------------------
   Hook for logging
----------------------------------------- */
static int logdir_log_transaction(request_rec *r) {
    logdir_config *conf = ap_get_module_config(r->server->module_config, &logdir_improved_module);
    if (!conf || (!conf->logdir_path && !conf->log_file_format)) {
        return OK; // We don't want to stop other log modules
    }

    if (conf->disable_standard_log) {
        return DECLINED; // This is a safer way to "disable" it for this request
    }

    const char *log_path = NULL;
    char errbuf[256];
    
    if (conf->log_file_expr) {
        log_path = ap_expr_str_exec(r, conf->log_file_expr, &errbuf);
    } else if (conf->logdir_path) {
        log_path = apr_pstrcat(r->pool, conf->logdir_path, "/access.log", NULL);
    }

    if (!log_path || !log_path[0]) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_logdir_improved: Log file path expression evaluated to empty string or no path configured.");
        return DECLINED;
    }
    
    const char *normalized_path = NULL;
    apr_status_t rv_path = apr_filepath_merge(&normalized_path, ap_server_root_relative(r->pool, log_path), NULL, APR_FILEPATH_TRUSTRUNTIME, conf->logger_pool);
    if (rv_path != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv_path, r,
                      "mod_logdir_improved: Failed to normalize log path '%s': %s", log_path, apr_strerror(rv_path, errbuf, sizeof(errbuf)));
        return DECLINED;
    }

    if ((r->connection->requests % conf->requests_before_gc) == 0) {
        apr_thread_mutex_lock(conf->logger_mutex);
        close_stale_loggers(conf, r->pool);
        apr_thread_mutex_unlock(conf->logger_mutex);
    }

    apr_thread_mutex_lock(conf->logger_mutex);

    logger_entry *logger_info = apr_hash_get(conf->loggers, normalized_path, APR_HASH_KEY_STRING);
    apr_file_t *log_file = logger_info ? logger_info->file : NULL;

    if (!log_file) {
        apr_status_t rv;
        const char *dir_path = NULL;
        rv = apr_filepath_dirname(&dir_path, normalized_path, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "mod_logdir_improved: Failed to get directory name for path '%s': %s", normalized_path, apr_strerror(rv, errbuf, sizeof(errbuf)));
            apr_thread_mutex_unlock(conf->logger_mutex);
            return DECLINED;
        }

        if (access(dir_path, F_OK) != 0 || (lstat(dir_path, &st) == 0 && st.st_uid != conf->uid)) {
            if (create_secure_logdir(r->server, dir_path, conf->uid, conf->gid) != APR_SUCCESS) {
                apr_thread_mutex_unlock(conf->logger_mutex);
                return DECLINED;
            }
        }

        rv = apr_file_open(&log_file, normalized_path, APR_APPEND | APR_CREATE | APR_WRITE | APR_SHARELOCK | APR_FOPEN_LARGEFILE, APR_OS_DEFAULT, conf->logger_pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "mod_logdir_improved: Could not open log file '%s': %s", normalized_path, apr_strerror(rv, errbuf, sizeof(errbuf)));
            apr_thread_mutex_unlock(conf->logger_mutex);
            return DECLINED;
        }
        
        apr_os_file_t osfd;
        rv = apr_os_file_get(&osfd, log_file);
        if (rv == APR_SUCCESS) {
            if (fchmod(osfd, S_IRUSR | S_IWUSR | S_IRGRP) == -1) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                              "mod_logdir_improved: Failed to set permissions on log file '%s': %s", normalized_path, strerror(errno));
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "mod_logdir_improved: Failed to get OS file descriptor for '%s': %s", normalized_path, apr_strerror(rv, errbuf, sizeof(errbuf)));
        }
        
        logger_info = apr_pcalloc(conf->logger_pool, sizeof(logger_entry));
        logger_info->file = log_file;
        logger_info->last_access = apr_time_now();
        apr_hash_set(conf->loggers, apr_pstrdup(conf->logger_pool, normalized_path), APR_HASH_KEY_STRING, logger_info);
        
    } else {
        logger_info->last_access = apr_time_now();
    }
    apr_thread_mutex_unlock(conf->logger_mutex);

    apr_pool_t *temp_pool;
    apr_pool_create(&temp_pool, r->pool);
    char *log_entry = NULL;
    
#if AP_MODULE_MAGIC_AT_LEAST(20111130, 0)
    log_entry = ap_log_format(temp_pool, r, conf->log_entry_format);
#else
    // Fallback for Apache 2.2: Common Log Format
    const char *remote_host = ap_get_remote_host(r->connection, r->per_dir_config, AP_REMOTE_NAME, NULL);
    const char *remote_logname = ap_get_remote_logname(r);
    const char *remote_user = ap_get_remote_user(r);
    const char *time_str = ap_log_request_time(temp_pool, r);
    const char *request_line = ap_escape_log_item(temp_pool, r->the_request);
    
    apr_off_t bytes_sent = r->bytes_sent;
    char *bytes_sent_str = NULL;
    if (bytes_sent > 0) {
        bytes_sent_str = apr_off_t_pbrk(temp_pool, bytes_sent);
    } else {
        bytes_sent_str = apr_pstrdup(temp_pool, "-");
    }
    
    log_entry = apr_pstrcat(temp_pool,
                            remote_host ? remote_host : "-", " ",
                            remote_logname ? remote_logname : "-", " ",
                            remote_user ? remote_user : "-", " ",
                            time_str, " ",
                            "\"", request_line ? request_line : "-", "\" ",
                            apr_psprintf(temp_pool, "%d", r->status), " ",
                            bytes_sent_str,
                            NULL);
#endif

    if (!log_entry) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_logdir_improved: Failed to format log entry.");
        apr_pool_destroy(temp_pool);
        return DECLINED;
    }

    apr_thread_mutex_lock(conf->logger_mutex);
    logger_info = apr_hash_get(conf->loggers, normalized_path, APR_HASH_KEY_STRING);
    
    if (logger_info) {
        apr_size_t log_entry_len = strlen(log_entry);
        apr_status_t write_rv = apr_file_write(logger_info->file, log_entry, &log_entry_len);
        if (write_rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, write_rv, r,
                          "mod_logdir_improved: Could not write to log file '%s': %s", normalized_path, apr_strerror(write_rv, errbuf, sizeof(errbuf)));
        } else {
            write_rv = apr_file_putc('\n', logger_info->file);
            if (write_rv != APR_SUCCESS) {
                 ap_log_rerror(APLOG_MARK, APLOG_ERR, write_rv, r,
                               "mod_logdir_improved: Could not write newline to log file '%s': %s", normalized_path, apr_strerror(write_rv, errbuf, sizeof(errbuf)));
            }
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_logdir_improved: Log file was closed by another process or GC. Not writing.");
    }

    apr_thread_mutex_unlock(conf->logger_mutex);
    apr_pool_destroy(temp_pool);

    return DECLINED;
}

/* -----------------------------------------
   Graceful Restart support
----------------------------------------- */
static int logdir_child_init(apr_pool_t *p, server_rec *s) {
    logdir_config *conf = ap_get_module_config(s->module_config, &logdir_improved_module);
    if (conf) {
        apr_thread_mutex_lock(conf->logger_mutex);
        if (conf->logger_pool) {
            apr_pool_destroy(conf->logger_pool);
        }
        apr_pool_create(&conf->logger_pool, p);
        conf->loggers = apr_hash_make(conf->logger_pool);
        apr_thread_mutex_unlock(conf->logger_mutex);
    }
    return OK;
}

/* -----------------------------------------
   Directives & registration
----------------------------------------- */
static const command_rec logdir_improved_cmds[] = {
    AP_INIT_TAKE1("LogDirPath", set_logdir_path, NULL, RSRC_CONF,
                  "Path to log directory (base path)"),
    AP_INIT_TAKE1("LogDirUser", set_logdir_user, NULL, RSRC_CONF,
                  "User for log directory ownership"),
    AP_INIT_TAKE1("LogDirGroup", set_logdir_group, NULL, RSRC_CONF,
                  "Group for log directory ownership"),
    AP_INIT_TAKE1("LogFileFormat", set_log_file_format, NULL, RSRC_CONF,
                  "Dynamic log file path format string (Apache 2.4+)"),
    AP_INIT_TAKE1("LogEntryFormat", set_log_entry_format, NULL, RSRC_CONF,
                  "Dynamic log entry format string (e.g., %h %u %r)"),
    AP_INIT_TAKE1("LogDirGCInterval", set_log_gc_interval, NULL, RSRC_CONF,
                  "FD garbage collection interval in seconds (default: 300)"),
    AP_INIT_TAKE1("LogDirRequestsBeforeGC", set_requests_before_gc, NULL, RSRC_CONF,
                  "Number of requests before running garbage collection (default: 100)"),
    AP_INIT_FLAG("LogDirDisableStandard", set_disable_standard_log, NULL, RSRC_CONF,
                 "Set to On to disable standard access logging when this module is active."),
    { NULL }
};

static void logdir_improved_register_hooks(apr_pool_t *p) {
    ap_hook_log_transaction(logdir_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(logdir_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA logdir_improved_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_logdir_config,
    merge_logdir_config,
    logdir_improved_cmds,
    logdir_improved_register_hooks
};
