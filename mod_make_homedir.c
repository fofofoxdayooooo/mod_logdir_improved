/*
 * mod_make_homedir.c - A module for ensuring the existence of a secure directory
 *
 * This module is designed to solve the problem of missing document roots or
 * other critical directories that can cause Apache graceful restarts to fail.
 * It ensures a specified directory and its parent path exist with the
 * correct permissions and ownership.
 *
 * Features:
 * - Per-VirtualHost configuration via directives:
 * - MakeHomedirPath <path>
 * - MakeHomedirUser <username>
 * - MakeHomedirGroup <groupname>
 * - MakeHomedirPerms <permissions> (new)
 *
 * - Automatically creates directories and their parents (`mkdir -p` style).
 * - Enforces secure permissions and ownership (`chown`) to a specified user/group.
 * - Protects against symlink attacks using `lstat`.
 * - Actively corrects permissions if they are improperly changed by external processes.
 *
 * Compilation:
 * apxs -i -a -c mod_make_homedir.c
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_errno.h"
#include "apr_hash.h"
#include "apr_lib.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#ifndef APLOG_USE_MODULE
#define APLOG_USE_MODULE make_homedir
#endif

module AP_MODULE_DECLARE_DATA make_homedir_module;

/* -----------------------------------------
   Per-server configuration
----------------------------------------- */
typedef struct {
    const char *base_path;
    const char *username;
    const char *groupname;
    uid_t uid;
    gid_t gid;
    mode_t perms;
    int is_configured;
} make_homedir_config;

/* New structure for multiple entries */
typedef struct {
    const char *path;
    const char *username;
    const char *groupname;
    const char *perms_str;
    uid_t uid;
    gid_t gid;
    mode_t perms;
} make_homedir_entry_t;

typedef struct {
    apr_array_header_t *entries;
} make_homedir_config_t;

/* -----------------------------------------
   Static function declarations
----------------------------------------- */
static apr_status_t create_secure_recursive_dir(server_rec *s, const char *path, uid_t uid, gid_t gid, mode_t perms);
static int make_homedir_open_logs(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);

/* -----------------------------------------
   Configuration creation and merging
----------------------------------------- */
static void *create_make_homedir_config(apr_pool_t *p, server_rec *s) {
    make_homedir_config_t *conf = apr_pcalloc(p, sizeof(*conf));
    conf->entries = apr_array_make(p, 5, sizeof(make_homedir_entry_t));
    return conf;
}

static void *merge_make_homedir_config(apr_pool_t *p, void *basev, void *addv) {
    make_homedir_config_t *base = (make_homedir_config_t*)basev;
    make_homedir_config_t *add  = (make_homedir_config_t*)addv;
    make_homedir_config_t *conf = apr_pcalloc(p, sizeof(*conf));
    
    conf->entries = apr_array_append(p, base->entries, add->entries);

    return conf;
}

/* -----------------------------------------
   Directive handlers
----------------------------------------- */
static const char *set_make_homedir_entry(cmd_parms *cmd, void *mconfig, const char *path_arg, const char *user_arg, const char *group_arg, const char *perms_arg) {
    make_homedir_config_t *conf = (make_homedir_config_t*)mconfig;
    make_homedir_entry_t *entry = apr_array_push(conf->entries);

    entry->path = ap_server_root_relative(cmd->pool, path_arg);
    if (!entry->path) {
        return "MakeHomedirEntries: Path must be a valid path relative to ServerRoot.";
    }

    entry->username = user_arg;
    entry->groupname = group_arg;
    entry->perms_str = perms_arg;
    
    struct passwd *pw = getpwnam(user_arg);
    if (!pw) {
        return apr_pstrcat(cmd->pool, "MakeHomedirEntries: Invalid user: ", user_arg, NULL);
    }
    entry->uid = pw->pw_uid;

    struct group *gr = getgrnam(group_arg);
    if (!gr) {
        return apr_pstrcat(cmd->pool, "MakeHomedirEntries: Invalid group: ", group_arg, NULL);
    }
    entry->gid = gr->gr_gid;
    
    if (sscanf(perms_arg, "%o", &entry->perms) != 1) {
        return apr_pstrcat(cmd->pool, "MakeHomedirEntries: Invalid octal permissions: ", perms_arg, NULL);
    }

    return NULL;
}

/* -----------------------------------------
   Core functionality
----------------------------------------- */
static apr_status_t create_secure_recursive_dir(server_rec *s, const char *path, uid_t uid, gid_t gid, mode_t perms) {
    struct stat st;
    apr_pool_t *temp_pool;
    apr_pool_create(&temp_pool, s->process->pconf);
    
    char *parent_path = apr_pstrdup(temp_pool, path);
    char *slash = parent_path;
    
    if (*slash == '/') {
        slash++;
    }
    
    while ((slash = strchr(slash, '/')) != NULL) {
        *slash = '\0';
        
        if (mkdir(parent_path, perms) == -1) {
            if (errno != EEXIST) {
                ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                             "mod_make_homedir: Failed to create parent directory %s: %s", parent_path, strerror(errno));
                apr_pool_destroy(temp_pool);
                return APR_EGENERAL;
            }
        }
        
        // Verify permissions and ownership.
        if (lstat(parent_path, &st) == 0) {
            if (!S_ISDIR(st.st_mode)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "mod_make_homedir: Path %s exists but is not a directory.", parent_path);
                apr_pool_destroy(temp_pool);
                return APR_EGENERAL;
            }
            if (st.st_uid != uid || st.st_gid != gid) {
                if (chown(parent_path, uid, gid) == -1) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                                 "mod_make_homedir: Failed to chown parent directory %s: %s", parent_path, strerror(errno));
                    apr_pool_destroy(temp_pool);
                    return APR_EGENERAL;
                }
            }
            if ((st.st_mode & perms) != perms) {
                 if (chmod(parent_path, perms) == -1) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                                 "mod_make_homedir: chmod failed for %s: %s", parent_path, strerror(errno));
                    apr_pool_destroy(temp_pool);
                    return APR_EGENERAL;
                }
            }
        }
        
        *slash = '/'; // Restore the slash
        slash++;
    }

    // Now, create the final directory
    if (mkdir(path, perms) == -1) {
        if (errno != EEXIST) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                         "mod_make_homedir: Failed to create final directory %s: %s", path, strerror(errno));
            apr_pool_destroy(temp_pool);
            return APR_EGENERAL;
        }
    }

    // Verify final directory permissions and ownership.
    if (lstat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mod_make_homedir: Path %s exists but is not a directory.", path);
            apr_pool_destroy(temp_pool);
            return APR_EGENERAL;
        }
        if (st.st_uid != uid || st.st_gid != gid) {
            if (chown(path, uid, gid) == -1) {
                ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                             "mod_make_homedir: Failed to chown %s to %ld:%ld: %s", path, (long)uid, (long)gid, strerror(errno));
                apr_pool_destroy(temp_pool);
                return APR_EGENERAL;
            }
        }
        if ((st.st_mode & perms) != perms) {
             if (chmod(path, perms) == -1) {
                ap_log_error(APLOG_MARK, APLOG_ERR, errno, s,
                             "mod_make_homedir: chmod failed for %s: %s", path, strerror(errno));
                apr_pool_destroy(temp_pool);
                return APR_EGENERAL;
            }
        }
    }
    
    apr_pool_destroy(temp_pool);
    return APR_SUCCESS;
}

/* -----------------------------------------
   Apache Hooks
----------------------------------------- */
static int make_homedir_open_logs(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
    make_homedir_config_t *conf = ap_get_module_config(s->module_config, &make_homedir_module);
    make_homedir_entry_t *entries;
    int i;
    
    if (conf && conf->entries) {
        entries = (make_homedir_entry_t*)conf->entries->elts;
        for (i = 0; i < conf->entries->nelts; i++) {
            make_homedir_entry_t *entry = &entries[i];
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "mod_make_homedir: Processing entry for path %s", entry->path);
            if (create_secure_recursive_dir(s, entry->path, entry->uid, entry->gid, entry->perms) != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }
    return OK;
}

static void make_homedir_register_hooks(apr_pool_t *p) {
    ap_hook_open_logs(make_homedir_open_logs, NULL, NULL, APR_HOOK_FIRST);
}

/* -----------------------------------------
   Module Directives
----------------------------------------- */
static const command_rec make_homedir_cmds[] = {
    AP_INIT_TAKE4("MakeHomedirEntries", set_make_homedir_entry, NULL, RSRC_CONF,
                  "Specify multiple directories to ensure existence, with path, user, group, and permissions (octal)."),
    { NULL }
};

/* -----------------------------------------
   Module Registration
----------------------------------------- */
module AP_MODULE_DECLARE_DATA make_homedir_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_make_homedir_config,
    merge_make_homedir_config,
    make_homedir_cmds,
    make_homedir_register_hooks
};
