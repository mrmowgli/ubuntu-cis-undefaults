#! /bin/sh
# This file changes permisions for various system level security sections.
# Each entry starts with the core CIS rule ID that it pertains to, and a comment explaining the rationale.
echo These scripts will change configuration settings for your system. They assume Ubuntu 20.04 LTS.
read -p "You must be root to run these scripts. Type Y to continue" OK
if [ $OK != "Y" ]; then
  echo Cancelling. ;
  exit 1 
fi

# Install audit and FS tools
apt-get install aide aide-common auditd
aideinit

## Audits
# 4.1.2 Turn on auditing - You don't know you need it til you need it.
systemctl enable auditd

# 4.1.3 Audits in boot - Turn on auditing during boot.  This only works if we haven't changed `GRUB_CMDLINE_LINUX`
sed -i.bak 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1"/g' /etc/default/grub


## System and Services
# 1.5.1 Ensure core dumps are restricted. A core dump is the memory of an executable program. 
# It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. 
# The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.
echo '* hard core 0'  > /etc/security/limits.d/10_restrict_core_dumps.conf
echo fs.suid_dumpable = 0 > /etc/sysctl.d/11_no_core_dumps.conf 
# Run the following command to set the active kernel parameter:
sysctl -w fs.suid_dumpable=0

# 1.5.3 Ensure address space layout randomization (ASLR) is enabled. Randomly placing virtual memory regions will make it 
# difficult to write memory page exploits as the memory placement will be consistently shifting.
echo kernel.randomize_va_space = 2 > /etc/sysctl.d/10_randomize_memory.conf
# Run the following command to set the active kernel parameter: # 
sysctl -w kernel.randomize_va_space=2

# 5.1 Ensure local login warning banner is configured properly. Avoid system information in the banner.
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue

# 1.7.2 Gnome3 Banner. Ensure GDM login banner is configured.  See note 5.1
sed -i "s/\[org\/gnome\/login-screen\]/\[org\/gnome\/login-screen\]\nbanner-message-enable=true\nbanner-message-text='Authorized uses only. All activity may be monitored and reported.'\n/g" /etc/gdm3/greeter.dconf-defaults

# 2.2.3 Ensure Avahi Server is not enabled. Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. 
# Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. 
# For example, a user can plug a computer into a network and Avahi automatically finds printers to print to,
# files to look at and people to talk to, as well as network services running on the machine.
# Note: Automatic discovery of network services is not normally required for system functionality. It is recommended to disable the service to reduce the potential attach surface.
systemctl disable avahi-daemon

# 2.2.16 Ensure rsync service is not enabled. The rsyncd service presents a security risk as it uses unencrypted protocols for communication. Typical desktop users will not need this.
systemctl disable rsync

# 2.3.4 Ensure telnet client is not installed. The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol. Use SSH as a replacement.
apt-get remove telnet


## Networking
# Most of the measures in this section relate to routing. It is unlikely that you will need to comment out any of these for a typical desktop system.



## Filesystems
# Filesystems present a number of entrypoints into your system, with the largest issue being physical access.
# This section represents removal of filesystems you aren't likely to use.  By default these removals are commented out. Uncomment the filesystems you are *NOT* using.

# 1.1.22 Keeps the system from automatically mounting devices when they are plugged in. If you are on a desktop, leave commented.
# sudo systemctl disable autofs

# 1.1.1.1 Remove freexvs (loaded by default). Unlikely to be used.
echo install freevxfs /bin/true > /etc/modprobe.d/freevxfs.conf
rmmod freevxfs

# 1.1.1.2 Remove jffs2 (loaded by default) Unlikely to be used.
echo install jffs2 /bin/true > /etc/modprobe.d/jffs2.conf
rmmod jffs2

# 1.1.1.3 Remove hfs (original MacOS fs, non-journaling.  Loaded by default) If you think you need this then comment the next two lines out.
echo install hfs /bin/true > /etc/modprobe.d/hfs.conf
rmmod hfs

# 1.1.1.4 Remove hfsplus (MacOS journaling FS.  Loaded by default) If you think you need this then comment the next two lines out.
echo install hfsplus /bin/true > /etc/modprobe.d/hfsplus.conf
rmmod hfsplus

# 1.1.1.5 Remove UDF (DVD and other long term storage formats) If you don't have a CD/DVD/Blueray or tapedrive you should uncomment the next two lines.
# sudo echo install udf /bin/true > /etc/modprobe.d/udf.conf
# sudo rmmod udf

# /tmp fs configurations.  By default there is no mount for /tmp and it is world writeable. This location should be with the noexec option to keep someone from writing executable code and running it from there.
# The following are related, but currently the default partitioning doesn't include /tmp.  
# This next section is primarily a breakdown of steps for remediation as comments. These are only useful if /tmp has it's own partition.
# TODO: Add support later for tmpfs

# 1.1.2 The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.
# Description: Since the /tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a 
#   separate partition. In addition, making /tmp its own file system allows an administrator to set the noexec option on the mount,
#   making /tmp useless for an attacker to install executable code. 
#   It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program
#   was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a
#   security vulnerability, the attacker could continue to exploit the known flaw.
# Remediation: Configure /etc/fstab as appropriate. 
# Example: tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0 
#    OR
# Run the following commands to enable systemd /tmp mounting: 
# sudo systemctl unmask tmp.mount && sudo systemctl enable tmp.mount 
# Edit /etc/systemd/system/local-fs.target.wants/tmp.mount to configure the /tmp mount

# 1.1.3 Add the nodev mount option to /tmp, which specifies that the filesystem cannot contain special devices.
# Description: Since the /tmp filesystem is not intended to support devices, set this option to ensure that users 
#   cannot attempt to create block or character special devices in /tmp.
# Remediation: Edit /etc/systemd/system/local-fs.target.wants/tmp.mount to configure the /tmp mount and run the following commands 
#   to enable systemd /tmp mounting: 
#   sudo systemctl unmask tmp.mount && sudo systemctl enable tmp.mount

# 1.1.4 Add the nosuid mount option to the /tmp mount. Specifies that the filesystem cannot contain set userid files.
# Description: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create set userid files in /tmp.
# Remediation: Edit /etc/systemd/system/local-fs.target.wants/tmp.mount to add nodev to the /tmp mount options: [Mount] Options=mode=1777,strictatime,noexec,nodev,nosuid 
#   Run the following command to remount /tmp : # mount -o remount,nodev /tmp

# 1.1.8 The nodev mount option specifies that the filesystem cannot contain special devices.
# Description: Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /var/tmp.
# Remediation: 
#   Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /var/tmp partition. See the fstab(5) manual page for more information. 
#   Then run the following command to remount /var/tmp : # sudo mount -o remount,nodev /var/tmp

# 1.1.9 For the /var/tmp mount, set the nosuid mount option which specifies that the filesystem cannot contain setuid files.
# Description: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /var/tmp.
# Remediation: Edit the /etc/fstab file and add nosuid to the fourth field (mounting options) for the /var/tmp partition. See the fstab(5) manual page for more information. 
#   Then run the following command to remount /var/tmp: # sudo mount -o remount,nosuid /var/tmp

# 1.1.10 For the /var/tmp mount, set the noexec mount option which specifies that the filesystem cannot contain executable binaries.
# Description: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /var/tmp.
# Remediation: Edit the /etc/fstab file and add noexec to the fourth field (mounting options) for the /var/tmp partition. See the fstab(5) manual page for more information.
#   Then run the following command to remount /var/tmp: # sudo mount -o remount,noexec /var/tmp

# 1.1.14 For the /home parition mount add the nodev option.
# Description: When set on a file system, this option prevents character and block special devices from being defined, or if they exist, from being used as character and block special devices.
# Remediation: Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /home partition. See the fstab(5) manual page for more information. 
#   Then run the command: sudo mount -o remount,nodev /home

# 1.1.17 Set the noexec mount option for /dev/shm, whicy specifies that the filesystem cannot contain executable binaries.
# Description: Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system.
# Remediation: Edit the /etc/fstab file and add noexec to the fourth field (mounting options) for the /dev/shm partition. See the fstab(5) manual page for more information. 
#   Then run the following command to remount /dev/shm: # sudo mount -o remount,noexec /dev/shm



# Printers
# 2.2.4 Disable cups - Uncomment if you are aren't planning on printing
# sudo systemctl disable cups

## Networking
# This section is primarily related to removing networking 'features' not typically useful on a normal workstation.
# 3.1.1 Ensure IP forwarding is disabled.  Setting the flags to 0 ensures that a system with multiple interfaces (for example, a hard proxy), will never be able to forward packets, and therefore, never serve as a router.
# A side effect of this is that you will be unable to use tethering to route on to your local network.
echo net.ipv4.ip_forward = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv6.conf.all.forwarding = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
sysctl -w net.ipv4.ip_forward=0 
sysctl -w net.ipv6.conf.all.forwarding=0 
sysctl -w net.ipv4.route.flush=1 
sysctl -w net.ipv6.route.flush=1

# 3.1.2 Ensure packet redirect sending is disabled. An attacker could use a compromised host to send invalid ICMP redirects to other router devices 
# in an attempt to corrupt routing and have users access a system set up by the attacker as opposed to a valid system.
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
echo net.ipv4.conf.default.send_redirects=0 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv4.conf.all.send_redirects=0  >> /etc/sysctl.d/10_CIS-hardening.conf

# 3.2.1 Ensure source routed packets are not accepted. In networking, source routing allows a sender to partially or fully specify the route packets take through a network. 
# In contrast, non-source routed packets travel a path determined by routers in the network. In some cases, systems may not be routable 
# or reachable from some locations (e.g. private addresses vs. Internet routable), and so source routed packets would need to be used.
echo net.ipv4.conf.all.accept_source_route = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv4.conf.default.accept_source_route = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv6.conf.all.accept_source_route = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv6.conf.default.accept_source_route = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1

# 3.2.2 Ensure ICMP redirects are not accepted. Attackers could use bogus ICMP redirect messages to maliciously alter the system routing tables 
# and get them to send packets to incorrect networks and allow your system packets to be captured.
echo net.ipv4.conf.all.accept_redirects = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv4.conf.default.accept_redirects = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv6.conf.all.accept_redirects = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv6.conf.default.accept_redirects = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1

# 3.2.3 Ensure secure ICMP redirects are not accepted. Secure ICMP redirects are the same as ICMP redirects, except they come from gateways 
# listed on the default gateway list. It is assumed that these gateways are known to your system, and that they are likely to be secure.
echo net.ipv4.conf.all.secure_redirects = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv4.conf.default.secure_redirects = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

# 3.2.4 Ensure suspicious packets are logged. When enabled, this feature logs packets with un-routable source addresses to the kernel log.
echo net.ipv4.conf.all.log_martians = 1 >> /etc/sysctl.d/10_CIS-hardening.conf 
echo net.ipv4.conf.default.log_martians = 1 >> /etc/sysctl.d/10_CIS-hardening.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

# 3.2.5 Ensure broadcast ICMP requests are ignored. Accepting ICMP echo and timestamp 
# requests with broadcast or multicast destinations for your network could be used to 
# trick your host into starting (or participating) in a Smurf attack. A Smurf attack 
# relies on an attacker sending large amounts of ICMP broadcast messages with a spoofed 
# source address. All hosts receiving this message and responding would send echo-reply 
# messages back to the spoofed address, which is probably not routable. If many hosts 
# respond to the packets, the amount of traffic on the network could be significantly multiplied.
echo net.ipv4.icmp_echo_ignore_broadcasts = 1 >> /etc/sysctl.d/10_CIS-hardening.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

# 3.2.6 Ensure bogus ICMP responses are ignored. Some routers (and some attackers) will 
# send responses that violate RFC-1122 and attempt to fill up a log file system with many useless error messages.
echo net.ipv4.icmp_ignore_bogus_error_responses = 1 >> /etc/sysctl.d/10_CIS-hardening.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1

# 3.2.7 Ensure Reverse Path Filtering is enabled. Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to 
# 1 forces the Linux kernel to utilize reverse path filtering on a received packet to determine if the packet was valid. 
# Essentially, with reverse path filtering, if the return packet does not go out the same interface that the corresponding 
# source packet came from, the packet is dropped (and logged if log_martians is set).
echo net.ipv4.conf.all.rp_filter = 1 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv4.conf.default.rp_filter = 1 >> /etc/sysctl.d/10_CIS-hardening.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

# 3.2.8 Ensure TCP SYN Cookies is enabled. ttackers use SYN flood attacks to perform a denial of service attacked on a system by sending many SYN packets without completing the three way handshake. 
# This will quickly use up slots in the kernel's half-open connection queue and prevent legitimate connections from succeeding. 
# SYN cookies allow the system to keep accepting valid connections, even if under a denial of service attack.
echo net.ipv4.tcp_syncookies = 1 >> /etc/sysctl.d/10_CIS-hardening.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

# 3.2.9 Ensure IPv6 router advertisements are not accepted. It is recommended that systems not accept router advertisements as they could be tricked into routing traffic to compromised machines.
echo net.ipv6.conf.all.accept_ra = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
echo net.ipv6.conf.default.accept_ra = 0 >> /etc/sysctl.d/10_CIS-hardening.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1

# TODO: Find some safe alternative.  While this is valid, it requires additional configuration of the network including static IP's
# 3.3.3 Ensure /etc/hosts.deny is configured. The /etc/hosts.deny file serves as a failsafe so that any host not specified in /etc/hosts.allow is denied access to the server.
# run the following command to create /etc/hosts.deny: # echo "ALL: ALL" >> /etc/hosts.deny

# 3.4.1 Ensure DCCP is disabled. If the protocol is not required, it is recommended that the drivers not be installed to reduce the potential attack surface.
# Edit or create a file in the /etc/modprobe.d/ directory ending in .conf Example: vim 
echo install dccp /bin/true > /etc/modprobe.d/dccp.conf

# 3.4.2 Ensure SCTP is disabled. If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
echo install sctp /bin/true > /etc/modprobe.d/sctp.conf 

# 3.4.3 Ensure RDS is disabled. If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
echo install rds /bin/true > /etc/modprobe.d/rds.conf

# 3.4.4 Ensure TIPC is disabled. If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface.
echo install tipc /bin/true > /etc/modprobe.d/tipc.conf

# TODO: Find a way to do some subset.  This rule WILL LOCK ALL TRAFFIC unless there is accompanying in/out rules.
# 3.5.1.1 Ensure default deny firewall policy. A default deny all policy on connections ensures that any unconfigured network usage will be rejected.
# notes: Changing firewall settings while connected over network can result in being locked out of the system. 
# Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well.
# iptables -P INPUT DROP 
# iptables -P OUTPUT DROP 
# iptables -P FORWARD DROP.

# TODO: This will only be temporary.
# 3.5.2.1: Ensure IPv6 default deny firewall policy.  A default deny all policy on connections ensures that any unconfigured network usage will be rejected. It is unlikely that you are currently 
# using IPv6 correclty or on purpose. 
# With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage.
# Run the following commands to implement a default DROP policy: 
ip6tables -P INPUT DROP 
ip6tables -P OUTPUT DROP 
ip6tables -P FORWARD DROP. 
# Notes: Changing firewall settings while connected over network can result in being locked out of the system.
# Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well.

# NOTE: Not configured. This requires adding a syslog server to your network, and is unlikely for a home configuration.
# 4.2.1.4: The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) 
# or to receive messages from remote hosts, reducing administrative overhead.
# Edit the /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files and add the 
# following line (where loghost.example.com is the name of your central log host): *.* @@loghost.example.com. Run the following command to reload the rsyslogd configuration: # pkill -HUP rsyslogd

# NOTE: Not configured. This requires adding a syslog server to your network, and is unlikely for a home configuration.
# 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts. By default, rsyslog does not listen for log messages coming in from remote systems. 
# The ModLoad tells rsyslog to load the imtcp.so module so it can listen over a network via TCP. The InputTCPServerRun option instructs rsyslogd to listen on the specified TCP port.
# For hosts that are designated as log hosts, edit the /etc/rsyslog.conf file and un-comment or add the following lines:$ModLoad imtcp & $InputTCPServerRun 514. 
# For hosts that are not designated as log hosts, edit the /etc/rsyslog.conf file and comment or remove the following lines: 
# $ModLoad imtcp 
# $InputTCPServerRun 514. 
# 
# Run the following command to reload the rsyslogd configuration: # pkill -HUP rsyslogd

# 5.1.8 Ensure at/cron is restricted to authorized users. 
# Run the following commands to remove /etc/cron.deny and /etc/at.deny and create and set permissions and ownership for /etc/cron.allow and /etc/at.allow:
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
