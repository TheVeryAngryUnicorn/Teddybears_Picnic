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
uname -a > /tmp/pentest/uname_"$HOSTNAME".txt
ps aux > /tmp/pentest/running_processes_"$HOSTNAME".txt
lsblk > /tmp/pentest/lsblk_"$HOSTNAME".txt
systemctl status > /tmp/pentest/systemctl_"$HOSTNAME".txt
crontab -l > /tmp/pentest/crontab_"$HOSTNAME".txt
lpstat -a > /tmp/pentest/printers_"$HOSTNAME".txt
lsof -i >> /tmp/pentest/lsof_"$HOSTNAME".txt

echo "Recruiting Networking Teddies"
#Grab Networking Info
ip a > /tmp/pentest/ip_a_"$HOSTNAME".txt
ifconfig -a > /tmp/pentest/ifconfig_"$HOSTNAME".txt
arp -a > /tmp/pentest/arp_"$HOSTNAME".txt
cat /etc/hosts > /tmp/pentest/hosts_"$HOSTNAME".tx
cat /etc/resolv.conf > /tmp/pentest/resolv_"$HOSTNAME".tx
netstat -pal > /tmp/pentest/netstat_"$HOSTNAM".txt
route -n > /tmp/pentest/route_"$HOSTNAM".txt

echo "Recruiting Firewall and AV Teddies"
sestatus > /tmp/pentest/selinux_"$HOSTNAME".txt
aa-status > /tmp/pentest/apparmour_"$HOSTNAME".txt
apparmor_status >> /tmp/pentest/apparmour_"$HOSTNAME".txt
echo CLAMAV > /tmp/pentest/AV_"$HOSTNAME".txt
ps aux | grep -i clam >> /tmp/pentest/AV_"$HOSTNAME".txt
echo "" >> /tmp/pentest/AV_"$HOSTNAME".txt
echo MCAFEE >> /tmp/pentest/AV_"$HOSTNAME".txt
ps aux | grep -i mcafee >> /tmp/pentest/AV_"$HOSTNAME".txt
iptables -L > /tmp/pentest/iptables_"$HOSTNAME".txt
systemctl status firewalld.service > /tmp/pentest/firewalld_"$HOSTNAME".txt
cat /proc/sys/kernel/randomize_va_space 2>/dev/null > /tmp/pentest/ASLR_"$HOSTNAME".txt


echo "Recruiting Package Teddies"
#Grab Packages Info
dpkg -l > /tmp/pentest/dpkg_"$HOSTNAME".txt
rpm -qa > /tmp/pentest/rpm_"$HOSTNAME".txt
find / \( -name "wget" -o -name "cc" -name "tftp" -o -name "ftp" -o -o -name "nmap" -o -name "perl" -o -name "nc" -o -name "netcat" -o -name "python" -o -name "gcc" -o -name "as" \) 2>/dev/null -ls > /tmp/pentest/Useful_Programs_"$HOSTNAME".txt
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null >> /tmp/pentest/Useful_Programs_"$HOSTNAME".txt

echo "Recruiting Conf Teddies"
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

echo "Recruiting Permission Teddies"
#Check For Naughty User Perms
ls -alR /home > /tmp/pentest/home_privs_"$HOSTNAME".txt
ls -alR /root > /tmp/pentest/root_home_privs_"$HOSTNAME".txt

#Check For Poor File Perms
find / -uid 0 -perm -4000 -type f 2>/dev/null -ls > /tmp/pentest/suid_root_"$HOSTNAME".txt
find / -perm -u=s -type f 2>/dev/null >> /tmp/pentest/suid_root_"$HOSTNAME".txt
find / -uid 0 -perm -2000 -type f 2>/dev/null -ls > /tmp/pentest/sgid_root_"$HOSTNAME".txt
find / -perm -g=s -type f 2>/dev/null >> /tmp/pentest/sgid_root_"$HOSTNAME".txt
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

echo "Recruiting File Teddies"
# Check the following 
find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls -la > /tmp/pentest/SSH_keys_"$HOSTNAME".txt

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

echo "Recruiting Password Teddies"
#Password Hunting
grep -rHi 'password=' /home/ > /tmp/pentest/home_password_"$HOSTNAME".txt
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null > /tmp/pentest/grep_password_"$HOSTNAME".txt
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \ > /tmp/pentest/find_password_"$HOSTNAME".txt

echo "Recruiting Capability Teddies"
#capability hunting
getcap -r / 2>/dev/null > /tmp/pentest/capabilities_BIN_"$HOSTNAME".txt
cat /etc/security/capability.conf | grep Cap > /tmp/pentest/capabilities_USER_"$HOSTNAME".txt


chmod 764 /tmp/pentest/"$HOSTNAME"_"$DATE" -R

echo "Picnic Time!!"
