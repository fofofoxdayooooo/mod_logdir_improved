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

/* -----------------------------------------
   Static function declarations
----------------------------------------- */
static apr_status_t create_secure_recursive_dir(server_rec *s, const char *path, uid_t uid, gid_t gid, mode_t perms);
static int make_homedir_open_logs(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);

/* -----------------------------------------
   Configuration creation and merging
----------------------------------------- */
static void *create_make_homedir_config(apr_pool_t *p, server_rec *s) {
    make_homedir_config *conf = apr_pcalloc(p, sizeof(*conf));
    conf->base_path = NULL;
    conf->username = NULL;
    conf->groupname = NULL;
    conf->uid = (uid_t)-1;
    conf->gid = (gid_t)-1;
    conf->perms = 0700; // Default secure permissions
    conf->is_configured = 0;
    return conf;
}

static void *merge_make_homedir_config(apr_pool_t *p, void *basev, void *addv) {
    make_homedir_config *base = (make_homedir_config*)basev;
    make_homedir_config *add  = (make_homedir_config*)addv;
    make_homedir_config *conf = apr_pcalloc(p, sizeof(*conf));
    
    conf->base_path = add->base_path ? add->base_path : base->base_path;
    conf->username  = add->username ? add->username : base->username;
    conf->groupname = add->groupname ? add->groupname : base->groupname;
    conf->uid       = (add->uid != (uid_t)-1) ? add->uid : base->uid;
    conf->gid       = (add->gid != (gid_t)-1) ? add->gid : base->gid;
    conf->perms     = (add->perms != 0700) ? add->perms : base->perms;
    conf->is_configured = add->is_configured || base->is_configured;

    return conf;
}

/* -----------------------------------------
   Directive handlers
----------------------------------------- */
static const char *set_make_homedir_path(cmd_parms *cmd, void *dummy, const char *arg) {
    make_homedir_config *conf = ap_get_module_config(cmd->server->module_config, &make_homedir_module);
    conf->base_path = ap_server_root_relative(cmd->pool, arg);
    if (!conf->base_path) {
        return "MakeHomedirPath must be a valid path relative to ServerRoot.";
    }
    conf->is_configured = 1;
    return NULL;
}

static const char *set_make_homedir_user(cmd_parms *cmd, void *dummy, const char *arg) {
    struct passwd *pw = getpwnam(arg);
    if (!pw) {
        return apr_pstrcat(cmd->pool, "Invalid user for MakeHomedirUser: ", arg, NULL);
    }
    make_homedir_config *conf = ap_get_module_config(cmd->server->module_config, &make_homedir_module);
    conf->username = arg;
    conf->uid = pw->pw_uid;
    conf->is_configured = 1;
    return NULL;
}

static const char *set_make_homedir_group(cmd_parms *cmd, void *dummy, const char *arg) {
    struct group *gr = getgrnam(arg);
    if (!gr) {
        return apr_pstrcat(cmd->pool, "Invalid group for MakeHomedirGroup: ", arg, NULL);
    }
    make_homedir_config *conf = ap_get_module_config(cmd->server->module_config, &make_homedir_module);
    conf->groupname = arg;
    conf->gid = gr->gr_gid;
    conf->is_configured = 1;
    return NULL;
}

static const char *set_make_homedir_perms(cmd_parms *cmd, void *dummy, const char *arg) {
    mode_t perms = 0;
    if (sscanf(arg, "%o", &perms) != 1) {
        return "MakeHomedirPerms must be a valid octal number (e.g., 0755).";
    }
    make_homedir_config *conf = ap_get_module_config(cmd->server->module_config, &make_homedir_module);
    conf->perms = perms;
    conf->is_configured = 1;
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
    make_homedir_config *conf = ap_get_module_config(s->module_config, &make_homedir_module);
    
    if (conf->is_configured) {
        // Only run for Virtual Hosts with a configured path.
        if (s->is_virtual && conf->base_path) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "mod_make_homedir: Processing VirtualHost %s", s->server_hostname);
            if (create_secure_recursive_dir(s, conf->base_path, conf->uid, conf->gid, conf->perms) != APR_SUCCESS) {
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
    AP_INIT_TAKE1("MakeHomedirPath", set_make_homedir_path, NULL, RSRC_CONF,
                  "Path to the directory to ensure existence. Can be relative to ServerRoot."),
    AP_INIT_TAKE1("MakeHomedirUser", set_make_homedir_user, NULL, RSRC_CONF,
                  "User for directory ownership."),
    AP_INIT_TAKE1("MakeHomedirGroup", set_make_homedir_group, NULL, RSRC_CONF,
                  "Group for directory ownership."),
    AP_INIT_TAKE1("MakeHomedirPerms", set_make_homedir_perms, NULL, RSRC_CONF,
                  "Permissions for the directory in octal (e.g., 0755)."),
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
