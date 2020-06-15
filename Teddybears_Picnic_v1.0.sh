#! /bin/bash

#Author
#The Very Angry Unicorn


DATE=`date +"%Y-%m-%d"`
WhoDis=$(whoami)

echo "script must be run as root or sudo!"

if [ "$WhoDis" != root ]; then
        echo "current user is $WhoDis, not root" >&2
        exit 1
fi

echo "Current User" && whoami
echo "Current Directory" && pwd

mkdir /tmp/pentest/
cd /tmp/pentest/
mkdir "$HOSTNAME"_"$DATE" 
cd "$HOSTNAME"_"$DATE"

chown $WhoDis /tmp/pentest/"$HOSTNAME"_"$DATE" -R

echo "Recruiting Teddies"
#Grab System Info
uname -a > uname_"$HOSTNAME".txt
netstat -pal > netstat_"$HOSTNAM".txt
ps aux > running_processes_"$HOSTNAME".txt
lsblk > lsblk_"$HOSTNAME".txt
systemctl status > systemctl_"$HOSTNAME".txt
crontab -l > crontab_"$HOSTNAME".txt
ip a > ip_a_"$HOSTNAME".txt
ifconfig -a > ifconfig_"$HOSTNAME".txt
lpstat -a > printers_"$HOSTNAME".txt
lsof -i >> lsof_"$HOSTNAME".txt

#Check System Security 
sestatus > selinux_"$HOSTNAME".txt
echo CLAMAV > AV_"$HOSTNAME".txt
ps aux | grep -i clam >> AV_"$HOSTNAME".txt
echo "" >> AV_"$HOSTNAME".txt
echo MCAFEE >> AV_"$HOSTNAME".txt
ps aux | grep -i mcafee >> AV_"$HOSTNAME".txt
iptables -L > iptables_"$HOSTNAME".txt
systemctl status firewalld.service > firewalld_"$HOSTNAME".txt

#Pull Interesting Files
cat /etc/shadow > shadow_"$HOSTNAME".txt
cat /etc/ssh/sshd_config > sshd_config_"$HOSTNAME".txt
cat /etc/passwd > passwd__"$HOSTNAME".txt
cat /etc/group > group_"$HOSTNAME".txt
cat /etc/sudoers > sudoers_"$HOSTNAME".txt
cat /etc/fstab > fstab_"$HOSTNAME".txt
cat /etc/rsyslog.conf > rsyslogconfig_"$HOSTNAME".txt
cat /etc/modprobe.d/CIS.conf > CIS_"$HOSTNAME".txt
cat /etc/hosts.allow > hosts_allow_"$HOSTNAME".txt
cat /etc/hosts.deny > hosts_deny_"$HOSTNAME".txt
cat /etc/postfix/main.cf >> mail_postfix_"$HOSTNAME".txt
cat /etc/chrony.conf > ntp_chrony_"$HOSTNAME".txt
cat /boot/grub2/grub.cfg > grub2_config_"$HOSTNAME".txt
cat /boot/grub2/user.cfg > grub_user_"$HOSTNAME".txt
cat /etc/services >> Services_"$HOSTNAME".txt

#Check For Naughty User Perms
ls -alR /home > home_privs_"$HOSTNAME".txt
ls -alR /root > root_home_privs_"$HOSTNAME".txt

#Check For Poor File Perms
find / -uid 0 -perm -4000 -type f 2>/dev/null -ls > suid_root_"$HOSTNAME".txt 
find / -uid 0 -perm -2000 -type f 2>/dev/null -ls > sgid_root_"$HOSTNAME".txt
find / -perm -4000 -type f 2>/dev/null -ls > suid_"$HOSTNAME".txt 
find / -perm -2000 -type f 2>/dev/null -ls > sgid_"$HOSTNAME".txt
find / -nouser 2>/dev/null -ls > no_user.txt
find / -nogroup 2>/dev/null -ls > no_group.txt
find / -perm -2 -type f 2>/dev/null -ls > World_Writable_files_"$HOSTNAME".txt
find / -perm -2 -type d 2>/dev/null -ls > World_Writeable_Dirs_"$HOSTNAME".txt
find / -perm /o=x -name "*.sh" 2>/dev/null -ls > world_Executable_scripts_"$HOSTNAME".txt
find / -perm /o=x -name "*.key" 2>/dev/null -ls > world_Executable_Keys_"$HOSTNAME".txt
find /var/log/ -perm /o=rwx 2>/dev/null -ls > Var_logs_other_Permission_"$HOSTNAME".txt
find /var/log -perm /go=rwx 2>/dev/null -ls > Var_logs_group_Permission_"$HOSTNAME".txt

# Check the following 
find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls -la > SSH_keys_"$HOSTNAME".txt

find / \( -name "wget" -o -name "nmap" -o -name "perl" -o -name "nc" -o -name "netcat" -o -name "python" -o -name "gcc" -o -name "as" \) 2>/dev/null -ls > Useful_Programs_"$HOSTNAME".txt

find / -type f -iname "*.conf" 2>/dev/null -ls > files_conf_"$HOSTNAME".txt
find / -type f -iname "*.log" 2>/dev/null -ls > files_log_"$HOSTNAME".txt
find / -type f -iname "*.cfg" 2>/dev/null -ls > files_cfg_"$HOSTNAME".txt
find / -type f -iname "*.properties" 2>/dev/null -ls > files_properties_"$HOSTNAME".txt
find / -type f -iname "*.sh" 2>/dev/null -ls > files_sh_"$HOSTNAME".txt
find / -type f -iname "*.yml" 2>/dev/null -ls > files_yml_"$HOSTNAME".txt
find / -type f -iname "*.yaml" 2>/dev/null -ls > files_yaml_"$HOSTNAME".txt
find / -type f -iname "*jar" 2>/dev/null -ls files_jar_"$HOSTNAME".txt
find / -type f -iname "*.key" 2>/dev/null -ls > files_key_"$HOSTNAME".txt
find / -type f -iname "*.csv" 2>/dev/null -ls > files_csv_"$HOSTNAME".txt
find / -type f -iname "*.ini" 2>/dev/null -ls > files_ini_"$HOSTNAME".txt
find / -type f -iname "*.xml" 2>/dev/null -ls > files_xml_"$HOSTNAME".txt
find / -type f -iname "*.old" 2>/dev/null -ls > files_old_"$HOSTNAME".txt

#Password Hunting
grep -rHi 'password=' /home/ > home_password_"$HOSTNAME".txt

chmod 764 /tmp/pentest/"$HOSTNAME"_"$DATE" -R

echo "Picnic Time!!"
