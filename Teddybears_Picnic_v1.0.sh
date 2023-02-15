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
uname -a > /tmp/pentest/uname_"$HOSTNAME".txt
netstat -pal > /tmp/pentest/netstat_"$HOSTNAM".txt
ps aux > /tmp/pentest/running_processes_"$HOSTNAME".txt
lsblk > /tmp/pentest/lsblk_"$HOSTNAME".txt
systemctl status > /tmp/pentest/systemctl_"$HOSTNAME".txt
crontab -l > /tmp/pentest/crontab_"$HOSTNAME".txt
ip a > /tmp/pentest/ip_a_"$HOSTNAME".txt
ifconfig -a > /tmp/pentest/ifconfig_"$HOSTNAME".txt
lpstat -a > /tmp/pentest/printers_"$HOSTNAME".txt
lsof -i >> /tmp/pentest/lsof_"$HOSTNAME".txt

#Check System Security 
sestatus > /tmp/pentest/selinux_"$HOSTNAME".txt
echo CLAMAV > /tmp/pentest/AV_"$HOSTNAME".txt
ps aux | grep -i clam >> /tmp/pentest/AV_"$HOSTNAME".txt
echo "" >> /tmp/pentest/AV_"$HOSTNAME".txt
echo MCAFEE >> /tmp/pentest/AV_"$HOSTNAME".txt
ps aux | grep -i mcafee >> /tmp/pentest/AV_"$HOSTNAME".txt
iptables -L > /tmp/pentest/iptables_"$HOSTNAME".txt
systemctl status firewalld.service > /tmp/pentest/firewalld_"$HOSTNAME".txt

#Pull Interesting Files
cat /etc/shadow > /tmp/pentest/shadow_"$HOSTNAME".txt
cat /etc/ssh/sshd_config > /tmp/pentest/sshd_config_"$HOSTNAME".txt
cat /etc/passwd > /tmp/pentest/passwd__"$HOSTNAME".txt
cat /etc/group > /tmp/pentest/group_"$HOSTNAME".txt
cat /etc/sudoers > /tmp/pentest/sudoers_"$HOSTNAME".txt
cat /etc/fstab > /tmp/pentest/fstab_"$HOSTNAME".txt
cat /etc/rsyslog.conf > /tmp/pentest/rsyslogconfig_"$HOSTNAME".txt
cat /etc/modprobe.d/CIS.conf > /tmp/pentest/CIS_"$HOSTNAME".txt
cat /etc/hosts.allow > /tmp/pentest/hosts_allow_"$HOSTNAME".txt
cat /etc/hosts.deny > /tmp/pentest/hosts_deny_"$HOSTNAME".txt
cat /etc/postfix/main.cf >> /tmp/pentest/mail_postfix_"$HOSTNAME".txt
cat /etc/chrony.conf > /tmp/pentest/ntp_chrony_"$HOSTNAME".txt
cat /boot/grub2/grub.cfg > /tmp/pentest/grub2_config_"$HOSTNAME".txt
cat /boot/grub2/user.cfg > /tmp/pentest/grub_user_"$HOSTNAME".txt
cat /etc/services >> /tmp/pentest/Services_"$HOSTNAME".txt

#Check For Naughty User Perms
ls -alR /home > /tmp/pentest/home_privs_"$HOSTNAME".txt
ls -alR /root > /tmp/pentest/root_home_privs_"$HOSTNAME".txt

#Check For Poor File Perms
find / -uid 0 -perm -4000 -type f 2>/dev/null -ls > /tmp/pentest/suid_root_"$HOSTNAME".txt 
find / -uid 0 -perm -2000 -type f 2>/dev/null -ls > /tmp/pentest/sgid_root_"$HOSTNAME".txt
find / -perm -4000 -type f 2>/dev/null -ls > /tmp/pentest/suid_"$HOSTNAME".txt 
find / -perm -2000 -type f 2>/dev/null -ls > /tmp/pentest/sgid_"$HOSTNAME".txt
find / -nouser 2>/dev/null -ls > /tmp/pentest/no_user.txt
find / -nogroup 2>/dev/null -ls > /tmp/pentest/no_group.txt
find / -perm -2 -type f 2>/dev/null -ls > /tmp/pentest/World_Writable_files_"$HOSTNAME".txt
find / -perm -2 -type d 2>/dev/null -ls > /tmp/pentest/World_Writeable_Dirs_"$HOSTNAME".txt
find / -perm /o=x -name "*.sh" 2>/dev/null -ls > /tmp/pentest/world_Executable_scripts_"$HOSTNAME".txt
find / -perm /o=x -name "*.key" 2>/dev/null -ls > /tmp/pentest/world_Executable_Keys_"$HOSTNAME".txt
find /var/log/ -perm /o=rwx 2>/dev/null -ls > /tmp/pentest/Var_logs_other_Permission_"$HOSTNAME".txt
find /var/log -perm /go=rwx 2>/dev/null -ls > /tmp/pentest/Var_logs_group_Permission_"$HOSTNAME".txt

# Check the following 
find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls -la > /tmp/pentest/SSH_keys_"$HOSTNAME".txt

find / \( -name "wget" -o -name "nmap" -o -name "perl" -o -name "nc" -o -name "netcat" -o -name "python" -o -name "gcc" -o -name "as" \) 2>/dev/null -ls > /tmp/pentest/Useful_Programs_"$HOSTNAME".txt

find / -type f -iname "*.conf" 2>/dev/null -ls > /tmp/pentest/files_conf_"$HOSTNAME".txt
find / -type f -iname "*.log" 2>/dev/null -ls > /tmp/pentest/files_log_"$HOSTNAME".txt
find / -type f -iname "*.cfg" 2>/dev/null -ls > /tmp/pentest/files_cfg_"$HOSTNAME".txt
find / -type f -iname "*.properties" 2>/dev/null -ls > /tmp/pentest/files_properties_"$HOSTNAME".txt
find / -type f -iname "*.sh" 2>/dev/null -ls > /tmp/pentest/files_sh_"$HOSTNAME".txt
find / -type f -iname "*.yml" 2>/dev/null -ls > /tmp/pentest/files_yml_"$HOSTNAME".txt
find / -type f -iname "*.yaml" 2>/dev/null -ls > /tmp/pentest/files_yaml_"$HOSTNAME".txt
find / -type f -iname "*jar" 2>/dev/null -ls /tmp/pentest/files_jar_"$HOSTNAME".txt
find / -type f -iname "*.key" 2>/dev/null -ls > /tmp/pentest/files_key_"$HOSTNAME".txt
find / -type f -iname "*.csv" 2>/dev/null -ls > /tmp/pentest/files_csv_"$HOSTNAME".txt
find / -type f -iname "*.ini" 2>/dev/null -ls > /tmp/pentest/files_ini_"$HOSTNAME".txt
find / -type f -iname "*.xml" 2>/dev/null -ls > /tmp/pentest/files_xml_"$HOSTNAME".txt
find / -type f -iname "*.old" 2>/dev/null -ls > /tmp/pentest/files_old_"$HOSTNAME".txt

#Password Hunting
grep -rHi 'password=' /home/ > /tmp/pentest/home_password_"$HOSTNAME".txt

chmod 764 /tmp/pentest/"$HOSTNAME"_"$DATE" -R

echo "Picnic Time!!"
