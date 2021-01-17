#! /bin/bash
# This script sets up more complex password requirements.
# It is not run by default as it adds some more stringent lockout strategies.
# BE AWARE: By NOT running these, you potentially open up your machine to 
# poor passwords and brute force attacks.
# Also note:  You should periodically run checks on passwords to ensure they have 
# a reasonable complexity.

# 5.3.1 Ensure password creation requirements are configured. Strong passwords protect systems from being hacked through brute force methods.
# 1) Run the following command to install the pam_pwquality module: 
apt-get install libpam-pwquality 

EXISTS=$( grep pam_pwquality.so /etc/pam.d/common-password )
if [[ $EXISTS == "" ]]; then   
  echo password requisite pam_pwquality.so retry=3 >> /etc/pam.d/common-password
fi

# At least one of each: digit, one uppercase, non-alpha, lowercase
echo minlen = 14 >> /etc/security/pwquality.conf
echo dcredit = -1 >> /etc/security/pwquality.conf
echo ucredit = -1 >> /etc/security/pwquality.conf
echo ocredit = -1 >> /etc/security/pwquality.conf
echo lcredit = -1 >> /etc/security/pwquality.conf

# 5.3.2 Ensure lockout for failed password attempts is configured. Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
echo auth required pam_tally2.so onerr=fail audit silent deny=6 unlock_time=900 >> /etc/pam.d/common-auth
# Note: If a user has been locked out because they have reached the maximum consecutive failure count defined by deny= in the pam_tally2.so module, 
# the user can be unlocked by issuing the command /sbin/pam_tally2 -u <username> --reset. 
# This command sets the failed count to 0, effectively unlocking the user. 
# Notes: Use of the "audit" keyword may log credentials in the case of user error during authentication. 

# 5.3.3 Ensure password reuse is limited. Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to guess the password.
# The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords.
echo password required pam_pwhistory.so remember=5 >> /etc/pam.d/common-password

# 5.4.1.1 Ensure password expiration is 365 days or less. The window of opportunity for an attacker to leverage compromised credentials or successfully compromise 
# credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity.
# Just FYI, a low complexity or common password can be cracked in a few days, sometimes a few minutes. A common period is every 30 days.
sed -i 's/PASS_MAX_DAYS	99999/PASS_MAX_DAYS 90/g' /etc/login.defs

# 5.4.1.2 Ensure minimum days between password changes is 7 or more. By restricting the frequency of password changes, an administrator can prevent users 
# from repeatedly changing their password in an attempt to circumvent password reuse controls.
sed -i 's/PASS_MIN_DAYS	0/PASS_MIN_DAYS 7/g' /etc/login.defs

# 5.4.1.4 Ensure inactive password lock is 30 days or less. Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies.
# This is currently commented out, as many home users are likely to set up a system and ignore it for great lengths of time. (Raspberry Pi, music server etc.)
# useradd -D -f 30

# 5.6 Ensure access to the su command is restricted
echo auth required pam_wheel.so >> /etc/pam.d/su
echo Create a comma separated list of users in the sudo statement in the /etc/group file: sudo:x:10:root,<user list>

