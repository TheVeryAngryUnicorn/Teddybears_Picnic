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

echo "Recruiting System Teddies"
#Grab System Info
uname -a > /tmp/pentest/"$HOSTNAME"_"$DATE"/uname_"$HOSTNAME".txt
ps aux > /tmp/pentest/"$HOSTNAME"_"$DATE"/running_processes_"$HOSTNAME".txt
lsblk > /tmp/pentest/"$HOSTNAME"_"$DATE"/lsblk_"$HOSTNAME".txt
systemctl status > /tmp/pentest/"$HOSTNAME"_"$DATE"/systemctl_"$HOSTNAME".txt
crontab -l > /tmp/pentest/"$HOSTNAME"_"$DATE"/crontab_"$HOSTNAME".txt
lpstat -a > /tmp/pentest/"$HOSTNAME"_"$DATE"/printers_"$HOSTNAME".txt
lsof -i > /tmp/pentest/"$HOSTNAME"_"$DATE"/lsof_"$HOSTNAME".txt

echo "Recruiting Networking Teddies"
#Grab Networking Info
ip a > /tmp/pentest/"$HOSTNAME"_"$DATE"/ip_a_"$HOSTNAME".txt
ifconfig -a > /tmp/pentest/"$HOSTNAME"_"$DATE"/ifconfig_"$HOSTNAME".txt
arp -a > /tmp/pentest/"$HOSTNAME"_"$DATE"/arp_"$HOSTNAME".txt
cat /etc/hosts > /tmp/pentest/"$HOSTNAME"_"$DATE"/hosts_"$HOSTNAME".tx
cat /etc/resolv.conf > /tmp/pentest/"$HOSTNAME"_"$DATE"/resolv_"$HOSTNAME".tx
netstat -pal > /tmp/pentest/"$HOSTNAME"_"$DATE"/netstat_"$HOSTNAME".txt
route -n > /tmp/pentest/"$HOSTNAME"_"$DATE"/route_"$HOSTNAME".txt

echo "Recruiting Firewall and AV Teddies"
sestatus > /tmp/pentest/"$HOSTNAME"_"$DATE"/selinux_"$HOSTNAME".txt
aa-status > /tmp/pentest/"$HOSTNAME"_"$DATE"/apparmour_"$HOSTNAME".txt
apparmor_status >> /tmp/pentest/"$HOSTNAME"_"$DATE"/apparmour_"$HOSTNAME".txt
echo CLAMAV > /tmp/pentest/"$HOSTNAME"_"$DATE"/AV_"$HOSTNAME".txt
ps aux | grep -i clam >> /tmp/pentest/"$HOSTNAME"_"$DATE"/AV_"$HOSTNAME".txt
echo "" >> /tmp/pentest/"$HOSTNAME"_"$DATE"/AV_"$HOSTNAME".txt
echo MCAFEE >> /tmp/pentest/"$HOSTNAME"_"$DATE"/AV_"$HOSTNAME".txt
ps aux | grep -i mcafee >> /tmp/pentest/"$HOSTNAME"_"$DATE"/AV_"$HOSTNAME".txt
iptables -L > /tmp/pentest/"$HOSTNAME"_"$DATE"/iptables_"$HOSTNAME".txt
systemctl status firewalld.service > /tmp/pentest/"$HOSTNAME"_"$DATE"/firewalld_"$HOSTNAME".txt
cat /proc/sys/kernel/randomize_va_space 2>/dev/null > /tmp/pentest/"$HOSTNAME"_"$DATE"/ASLR_"$HOSTNAME".txt


echo "Recruiting Package Teddies"
#Grab Packages Info
dpkg -l > /tmp/pentest/"$HOSTNAME"_"$DATE"/dpkg_"$HOSTNAME".txt
rpm -qa > /tmp/pentest/"$HOSTNAME"_"$DATE"/rpm_"$HOSTNAME".txt
find / \( -name "wget" -o -name "cc" -name "tftp" -o -name "ftp" -o -o -name "nmap" -o -name "perl" -o -name "nc" -o -name "netcat" -o -name "python" -o -name "gcc" -o -name "as" \) 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/Useful_Programs_"$HOSTNAME".txt
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null >> /tmp/pentest/"$HOSTNAME"_"$DATE"/Useful_Programs_"$HOSTNAME".txt

echo "Recruiting Conf Teddies"
#Pull Interesting Files
cat /etc/shadow > /tmp/pentest/"$HOSTNAME"_"$DATE"/shadow_"$HOSTNAME".txt
cat /etc/ssh/sshd_config > /tmp/pentest/"$HOSTNAME"_"$DATE"/sshd_config_"$HOSTNAME".txt
cat /etc/passwd > /tmp/pentest/"$HOSTNAME"_"$DATE"/passwd__"$HOSTNAME".txt
cat /etc/group > /tmp/pentest/"$HOSTNAME"_"$DATE"/group_"$HOSTNAME".txt
cat /etc/sudoers > /tmp/pentest/"$HOSTNAME"_"$DATE"/sudoers_"$HOSTNAME".txt
cat /etc/fstab > /tmp/pentest/"$HOSTNAME"_"$DATE"/fstab_"$HOSTNAME".txt
cat /etc/rsyslog.conf > /tmp/pentest/"$HOSTNAME"_"$DATE"/rsyslogconfig_"$HOSTNAME".txt
cat /etc/modprobe.d/CIS.conf > /tmp/pentest/"$HOSTNAME"_"$DATE"/CIS_"$HOSTNAME".txt
cat /etc/hosts.allow > /tmp/pentest/"$HOSTNAME"_"$DATE"/hosts_allow_"$HOSTNAME".txt
cat /etc/hosts.deny > /tmp/pentest/"$HOSTNAME"_"$DATE"/hosts_deny_"$HOSTNAME".txt
cat /etc/postfix/main.cf >> /tmp/pentest/"$HOSTNAME"_"$DATE"/mail_postfix_"$HOSTNAME".txt
cat /etc/chrony.conf > /tmp/pentest/"$HOSTNAME"_"$DATE"/ntp_chrony_"$HOSTNAME".txt
cat /boot/grub2/grub.cfg > /tmp/pentest/"$HOSTNAME"_"$DATE"/grub2_config_"$HOSTNAME".txt
cat /boot/grub2/user.cfg > /tmp/pentest/"$HOSTNAME"_"$DATE"/grub_user_"$HOSTNAME".txt
cat /etc/services >> /tmp/pentest/"$HOSTNAME"_"$DATE"/Services_"$HOSTNAME".txt

echo "Recruiting Permission Teddies"
#Check For Naughty User Perms
ls -alR /home > /tmp/pentest/"$HOSTNAME"_"$DATE"/home_privs_"$HOSTNAME".txt
ls -alR /root > /tmp/pentest/"$HOSTNAME"_"$DATE"/root_home_privs_"$HOSTNAME".txt

#Check For Poor File Perms
find / -uid 0 -perm -4000 -type f 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/suid_root_"$HOSTNAME".txt
find / -perm -u=s -type f 2>/dev/null >> /tmp/pentest/"$HOSTNAME"_"$DATE"/suid_root_"$HOSTNAME".txt
find / -uid 0 -perm -2000 -type f 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/sgid_root_"$HOSTNAME".txt
find / -perm -g=s -type f 2>/dev/null >> /tmp/pentest/"$HOSTNAME"_"$DATE"/sgid_root_"$HOSTNAME".txt
find / -perm -4000 -type f 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/suid_"$HOSTNAME".txt 
find / -perm -2000 -type f 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/sgid_"$HOSTNAME".txt
find / -nouser 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/no_user.txt
find / -nogroup 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/no_group.txt
find / -perm -2 -type f 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/World_Writable_files_"$HOSTNAME".txt
find / -perm -2 -type d 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/World_Writeable_Dirs_"$HOSTNAME".txt
find / -perm /o=x -name "*.sh" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/world_Executable_scripts_"$HOSTNAME".txt
find / -perm /o=x -name "*.key" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/world_Executable_Keys_"$HOSTNAME".txt
find /var/log/ -perm /o=rwx 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/Var_logs_other_Permission_"$HOSTNAME".txt
find /var/log -perm /go=rwx 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/Var_logs_group_Permission_"$HOSTNAME".txt

echo "Recruiting File Teddies"
# Check the following 
find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls -la > /tmp/pentest/"$HOSTNAME"_"$DATE"/SSH_keys_"$HOSTNAME".txt

find / -type f -iname "*.conf" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_conf_"$HOSTNAME".txt
find / -type f -iname "*.log" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_log_"$HOSTNAME".txt
find / -type f -iname "*.cfg" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_cfg_"$HOSTNAME".txt
find / -type f -iname "*.properties" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_properties_"$HOSTNAME".txt
find / -type f -iname "*.sh" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_sh_"$HOSTNAME".txt
find / -type f -iname "*.yml" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_yml_"$HOSTNAME".txt
find / -type f -iname "*.yaml" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_yaml_"$HOSTNAME".txt
find / -type f -iname "*jar" 2>/dev/null -ls /tmp/pentest/"$HOSTNAME"_"$DATE"/files_jar_"$HOSTNAME".txt
find / -type f -iname "*.key" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_key_"$HOSTNAME".txt
find / -type f -iname "*.csv" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_csv_"$HOSTNAME".txt
find / -type f -iname "*.ini" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_ini_"$HOSTNAME".txt
find / -type f -iname "*.xml" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_xml_"$HOSTNAME".txt
find / -type f -iname "*.old" 2>/dev/null -ls > /tmp/pentest/"$HOSTNAME"_"$DATE"/files_old_"$HOSTNAME".txt

echo "Recruiting Password Teddies"
#Password Hunting
grep -rHi 'password=' /home/ > /tmp/pentest/"$HOSTNAME"_"$DATE"/home_password_"$HOSTNAME".txt
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null > /tmp/pentest/"$HOSTNAME"_"$DATE"/grep_password_"$HOSTNAME".txt
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \ > /tmp/pentest/"$HOSTNAME"_"$DATE"/find_password_"$HOSTNAME".txt

echo "Recruiting Capability Teddies"
#capability hunting
getcap -r / 2>/dev/null > /tmp/pentest/capabilities_BIN_"$HOSTNAME".txt
cat /etc/security/capability.conf | grep Cap > /tmp/pentest/"$HOSTNAME"_"$DATE"/capabilities_USER_"$HOSTNAME".txt


chmod 764 /tmp/pentest/"$HOSTNAME"_"$DATE" -R

echo "Picnic Time!!"
