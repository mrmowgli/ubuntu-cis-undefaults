#! /bin/bash
# This is to automate the password creation for GRUB boot passwords.
# It prompts for a password twice, then writes the hashed PW to the `40_custom` grub config file.
echo This will create a boot password for Grub. For more information see CIS rule 1.4.2
echo The default username will be 'admin'. Please make a note of this and your password or you WILL NOT be able
echo log into your machine. Press CTRL-C to cancel.
echo 
EXISTS=$( grep superusers /etc/grub.d/40_custom )
if [[ $EXISTS != "" ]]; then 
  echo You already have a password set for grub! $EXISTS ;
  echo To change the password, manually configure /etc/grub.d/40_custom ;
  exit 2 ;
fi
read -p "Press Y then Enter to continue: " OK
if [ $OK != "Y" ]; then 
  echo Cancelling. ;
  exit 1 
fi

echo Enter your password, press ENTER then re-enter your password.
X=`grub-mkpasswd-pbkdf2`
GP=$( echo $X | gawk '{print $11;}' )
if [[ $GP == "" ]]; then
  echo Your passwords don\'t match. Cancelling.
  exit 2
fi
echo Your Hash: $GP
echo Adding your hash to /etc/grub.d/40_custom
sudo echo 'set superusers="admin"' >> /etc/grub.d/40_custom
sudo echo password_pbkdf2 admin $PW >> /etc/grub.d/40_custom
sudo update-grub

