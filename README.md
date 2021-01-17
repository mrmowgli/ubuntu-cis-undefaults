# Basic Security Audit configuration for new installs of Ubuntu 20.04lts.
By default Ubuntu desktop is configured with a very generic set of rules, allowing the most flexibility in terms of usage.
Unfortunately as a result there are many opportunities for strenthening the security and logging of your desktop that are not enabled.

This repository is based on CIS vulnerability audits and remediation.
These `suggestions` are usable by most common small enviroment desktop installs.

## CIS
These are based off of the Wazzuh Open IDS, generated from a default Ubuntu install.
The source code is easy to understand, please read through each set to insure it makes sense for your purposes.

### Section 1: System
1.4.3 Set the root user password. Require a password for the root account.
Requiring authentication in single user mode prevents an unauthorized user from rebooting the system into single user to gain root privileges without credentials.
`sudo passwd root`

2.2.3 Turn off Avahi service. Automatic discovery of network services is not normally required for system functionality. 
It is recommended to disable the service to reduce the potential attach surface.

2.2.4 Ensure CUPS is not enabled. These scripts do NOT turn off cups, as some people may use cups for printing.
The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability.
If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be disabled to reduce the potential attack surface.
Run the following command to disable cups: # `sudo systemctl disable cups`

1.5.1 Ensure core dumps are restricted. A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.

### Section 2: Partitions
For new installations, during installation create a custom partition setup and specify a separate partition for each
of the following mount points:
    * `/var` - Typically logs, sometimes DB's. A separate partition keeps the system from crashing if there is no space left.
    *  /var/tmp - similar to tmp, but not world writeable. A separate parition allows fine grained restrictions.
    * `/boot`- Your boot filesystem, make sure you keep enough space available in here to handle at least three kernels. 300Mb should suffice.
    * `/tmp` - This location is world writeable, allowing a variety of security issues if it's not locked down appropriately.
    * `/home` - This can also be an issue with block devices and SUID usages. Space issues here can also affect the system.

For systems that were previously installed, create new partitions and configure /etc/fstab as appropriate.

### Section 3: Audits
*Installing Audit:*
We need to add audits to our system as it is NOT installed by default. 
`sudo apt-get install auditd`

1.3.1 In addition we want to add tools to monitor our system state.  Here we install aide.  You may wish notifications to go somewhere,
but you are safe responding "No Configuration" during install.  For no notifications you can still get reports by calling `aide.wrapper`
```bash
# sudo apt-get install aide aide-common
# sudo aideinit
```

#### Configuration Changes for Audit:
`audit.conf` requires a few minor changes. (`/etc/audit/auditd.conf`)

```
# 4.1.1.1 Set default log size for audits (in mb)
max_log_file = 18
# 4.1.1.2 Halt when audit logs fill up
space_left_action = email 
action_mail_acct = root 
admin_space_left_action = halt
# 4.1.1.3 The max_log_file_action setting determines how to handle the audit log file reaching the max file size. A value of keep_logs will rotate the logs but never delete old logs. You may want to periodically remove old logs to save space.
max_log_file_action = keep_logs

```

`cis.rules` will hold all of our audit specific rules.  These will be merged into the parent `audit.rules`. 
Create (`/etc/audit/rules.d/cis.rules`)

TODO: Add rule for netcat (nc) auditing. Netcat is a tool that can exfiltrate data off of your system by redirecting files, including stdin, stdout and stderr.

```conf
# 4.1.4 Log clock changes for 32/64 bit
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change -a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
# 4.1.5 Record changes to our accounts
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
# Networking
# 4.1.6 Record changes to network environment files or system calls.
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/netplan/01-network-manager-all.yaml -p wa -k system-locale
# 4.1.8 Audit login failures
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
# 4.1.9 Monitor session initiation events
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
# 4.1.10 File permision changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
# 4.1.11 Monitor for unsuccessful attempts to access files.
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
# 4.1.13 Keep track of media mounted by non root users
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
# 4.1.14 Monitor the use of system calls associated with the deletion or renaming of files and file attributes.
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
# 4.1.15 Monitor scope changes for system administrations.
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
# 4.1.16 Monitor the sudo log file.
-w /var/log/sudo.log -p wa -k actions
# 4.1.17 Monitor the loading and unloading of kernel modules.
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
# 4.1.7 - Only valid if SELinux is enabled
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
# 4.1.18 Make this security file immutable
-e 2
```


