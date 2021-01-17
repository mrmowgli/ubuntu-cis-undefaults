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



