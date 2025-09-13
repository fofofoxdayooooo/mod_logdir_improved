# mod_logdir_improved

**mod_logdir_improved** is an Apache HTTP Server module that provides **per-virtual-host dynamic log directories** with secure ownership and automatic directory creation.  
It supports both **Apache 2.2 (fixed log path)** and **Apache 2.4+ (dynamic log paths with LogFormat expressions)**.

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

---

## Build & Install

```bash
# Requires Apache dev tools (apxs)
apxs -c -i -a mod_logdir_improved.c
This will build and install mod_logdir_improved.so into your Apache modules directory, and add a LoadModule directive into httpd.conf.
```

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
