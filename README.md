# mod_logdir_improved

**mod_logdir_improved** is an Apache HTTP Server module that provides **per-virtual-host dynamic log directories** with secure ownership and automatic directory creation.  
It supports both **Apache 2.2 (fixed log path)** and **Apache 2.4+ (dynamic log paths with LogFormat expressions)**.
And as a bonus, I created a module to solve Apache's Docroot problem. It's simple, but it fixes the issue where Apache fails to start if the home directory is missing during startup.
---

## Features

- **Dynamic log directories**  
  Automatically creates per-host/per-user/per-request log directories.  
  Directories are created with secure permissions (`0700`) and owned by the specified user/group.

- **Apache 2.4 LogFormat integration**  
  Uses Apache’s native `LogFormat` and `CustomLog` parsing for log entry generation.  
  No need to maintain a custom log parser inside the module.

- **Apache 2.2 fallback**  
  Falls back to a fixed `LogDirPath` with Common Log Format output.

- **Secure by default**  
  - Prevents TOCTOU issues with `lstat()` checks.  
  - Enforces UID/GID ownership.  
  - Ensures log files are created with `0640` permissions.  

- **File descriptor management**  
  - Configurable garbage collection (`LogDirGCInterval`, `LogDirRequestsBeforeGC`).  
  - Prevents unlimited file descriptor growth in shared hosting environments.  

- **Thread-safe**  
  Protects internal logger hash with `apr_thread_mutex`, compatible with `worker` and `event` MPM.

# mod_make_homedir

**mod_make_homedir** is an Apache HTTPD module that ensures the existence of critical directories such as `DocumentRoot`.  
It prevents Apache graceful restarts from failing when a VirtualHost’s home directory has been deleted or is missing.

- **Automatic Directory Creation**  
  Recursively creates directories (`mkdir -p` style).

- **Ownership and Permissions**  
  Ensures secure ownership (`chown`) and permissions (`0700`) for the target directory.

- **Symlink Protection**  
  Uses `lstat()` to verify directories are real directories (not symlinks).

- **Per-VirtualHost Configuration**  
  Configure directory paths, users, and groups on a per-host basis.

---

## Apache mod_make_homedir Compilation

```sh
apxs -i -a -c mod_make_homedir.c
```

---

## Build & Install

```bash
# Requires Apache dev tools (apxs)
apxs -c -i -a mod_logdir_improved.c
This will build and install mod_logdir_improved.so into your Apache modules directory, and add a LoadModule directive into httpd.conf.
```

Example Configuration
```apache
<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /home/user1/public_html

    # Ensure the DocumentRoot exists with secure ownership
    MakeHomedirEntries /home/user1/public_html user group 0700
    MakeHomedirEntries /home/user1/logs         user group 0750
    MakeHomedirEntries /home/user1/tmp          user group 0700

    ErrorLog logs/example.com_error.log
    CustomLog logs/example.com_access.log combined
</VirtualHost>
```

With this configuration:

 - If /var/www/example.com/public_html is missing, it will be recreated automatically.
 - Ownership will be set to apache:apache.
 - Permissions will be enforced as 0700.

## Logging

Any errors (failed mkdir, chown, or chmod) are reported to Apache’s error log.

## Use Case

This module is useful in shared hosting or automated environments where:

Users may accidentally delete their home directories.

Missing DocumentRoots cause Apache graceful restarts to fail.

Administrators want to ensure directories are always recreated securely.
---

## Configuration
Example for Apache 2.4+:
```apache
LoadModule logdir_module modules/mod_logdir_improved.so

<VirtualHost *:80>
    ServerName example.com

    # Base directory
    LogDirPath   /var/log/apache2/vhosts/example.com

    # Ownership
    LogDirUser   www-data
    LogDirGroup  www-data

    # Dynamic log file naming (per-client, per-date)
    LogFileFormat "%h/%Y-%m-%d/access.log"

    # Use standard LogFormat nickname
    LogEntryFormat combined

    # Garbage collection
    LogDirGCInterval 300
    LogDirRequestsBeforeGC 1000

    # Disable default CustomLog
    LogDirDisableStandard On
</VirtualHost>
```
For Apache 2.2, only LogDirPath is supported and logs are written in Common Log Format.

Example for apache2.2:
```apache
# Load Module
LoadModule logdir_module modules/mod_logdir_improved.so

<VirtualHost *:80>
    ServerName legacy.example.com

    # Base directory for logs
    LogDirPath   /var/log/apache2/vhosts/legacy.example.com

    # Specify owner
    LogDirUser   apache
    LogDirGroup  apache

    # Garbage collection settings (optional)
    # Clean up FD older than 300 seconds since last access
    LogDirGCInterval 300
    # Execute GC every 1000 requests
    LogDirRequestsBeforeGC 1000

    # Suppress standard CustomLog (to avoid duplicate logging)
    LogDirDisableStandard On
</VirtualHost>
```

## systemd tuning
Since dynamic logging may open many files, it’s recommended to increase the FD limit:


/etc/systemd/system/apache2.service.d/override.conf
```
[Service]
LimitNOFILE=65535
```

## License
MIT (or Apache License 2.0, depending on project policy).

作者：abe_yamagami
