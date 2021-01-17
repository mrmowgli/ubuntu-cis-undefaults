#! /bin/bash
cp ./cis.rules /etc/audit/rules.d/cis.rules
echo copied CIS audit rules to /etc/audit/rules.d/cis.rules
# Edit in place
# /etc/audit/auditd.conf
echo "Your audit log file will be 256mb.  When this limit is reached"
echo "Your system will be HALTED so that logs will not be lost."
echo "These rules are aggressive and require active monitoring of log file sizes."
read -p "To continue, type 'Y' then <RETURN>" OK
if [ $OK != "Y" ]; then
  echo Cancelling. ;
  exit 1 
fi

# 4.1.1.1 Set default log size for audits (in mb)
sed -i 's/max_log_file = 8/max_log_file = 256/g' /etc/audit/auditd.conf

# TODO: Ensure we completely set up email to a local only system account.
# 4.1.1.2 Halt when audit logs fill up
sed -i 's/space_left_action = SYSLOG/space_left_action = EMAIL/g' /etc/audit/auditd.conf
sed -i 's/admin_space_left_action = SUSPEND/admin_space_left_action = HALT/g' /etc/audit/auditd.conf
# 4.1.1.3 The max_log_file_action setting determines how to handle the audit log file reaching 
# the max file size. A value of keep_logs will rotate the logs but never delete old logs. 
# You may want to periodically remove old logs to save space.
sed -i 's/max_log_file_action = ROTATE/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf



