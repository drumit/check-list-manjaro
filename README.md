# check-list-manjaro
## Downloading  Manjaro Linux KDE Minimal

## 1. Burning the installation ISO to the USB storage device with Rufus
## 2. Installation
### 2.1 Set the username and password 
### 2.2 Set hostname
###### (hostname is compilation from 2 letters country name, + mac address pc)
###### The MAC address you'll see in the console (F12) with command ip addr | grep -E ether
###### Also choose a time zone (command in terminal tzselect)
## 3.	Preparing remote access to the machine

> sudo systemctl start sshd
> sudo systemctl status sshd
> sudo systemctl enable sshd

## 4.	Adding the network certificate to the desktop (with help USB, or SCP, for Linux remote system, or WinSCP for Windows remote system)

> sudo cp certificatename.crt /etc/ca-certificates/trust-source/anchors/
> sudo trust extract-compat

## 5.   Installing  yay and updating OS

> sudo pacman -Syyuu yay
> yay -Syyuu --nodiffmenu --nocleanmenu --noconfirm

## 6 Downloading software for users from Alliedium project repository

### 6.1 Cloning the repository

> git clone https://github.com/alliedium/awesome-linux-config.git

### 6.2 Go to the project folder

> cd awesome-linux-config/manjaro/basic/

### 6.3 Running the system-wide installation scripts.

> ./install_all.sh

## 7. Change directory to the sysadmin folder and follow the instructions from her.

> cd sysadmin

 Reboot PC
## 8. Downgrading the kernel version (sic!) to the current LTS version

> sudo mhwd-kernel –I linux54

 Reboot PC
 ```
In time reboot we must press Esc 
In the menu that opens, select the kernel version LTS (5.4 for now), and boot from it
Removing the newer kernel
```

> sudo mhwd-kernel –r linux

## 9. Checking for system updates

> yay -Syyuu --nodiffmenu --nocleanmenu --noconfirm

## 10. Installing software for adding host to Active Directory domain

> sudo pacman -S  krb5 sssd usbguard pam-krb5

 Reboot PC
## 11.	Checking current time

> date

## 12. Configuring the system.
### 12.1 Check and correct time settings

> sudo systemctl status ntpd 
> sudo systemctl status systemd-timesyncd 
> sudo systemctl start systemd-timesync 
> sudo systemctl enable systemd-timesync 

## 12.1.1 Change servers to our local time servers, then restart the service
> sudo nano /etc/systemd/timesyncd.conf
```
[Time]
NTP=0.arch.pool.ntp.org 1.arch.pool.ntp.org 2.arch.pool.ntp.org 3.arch.pool.ntp.org
FallbackNTP=0.pool.ntp.org 1.pool.ntp.org 0.fr.pool.ntp.org
```
## 12.1.2 Checking time settings

> timedatectl show-timesync --all
> timedatectl set-ntp true 
> timedatectl timesync-status

### 12.2 Customization krb5 (change the default values to the required ones)

> sudo nano /etc/krb5.conf
```
[appdefaults]
        encrypt = yes 
[libdefaults]
	default_realm = DOMAIN.COM
	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true
	fcc-mit-ticketflags = true
	dns_lookup_kdc = true
        dns_lookup_realm = true
        ticket_lifetime = 24h
        renew_lifetime = 7d
        rdns = false
        forwardable = yes
        clockskew = 300
        v4_instance_resolve = false
	default_tgs_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac
        default_tkt_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac
        permitted_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac
        v4_name_convert = {
                host = {
                        rcmd = host
                        ftp = ftp
                }
                        plain = {
			something = something-else
		}
        }
[realms]
	DOMAIN.COM = {
		kdc = dc.domain.com
		kdc = dc1.domain.com
		admin_server = dc.domain.com
		default_domain = DOMAIN.COM
	}
[domain_realm]
	.domain.com = DOMAIN.COM
	domain.com = DOMAIN.COM 
[login]
	krb4_convert = false
	krb4_get_tickets = false
	
```
### 12.3 Customization sssd (change the default values to the required ones)

> sudo nano /etc/sssd/sssd.conf 
```
[sssd]
  default_domain_suffix = domain.com
	domains = domain.com
	config_file_version = 2
	services = nss, pam
[nss]
	filter_users = root 
	shell_fallback = /sbin/nologin 
	fallback_homedir = /usr/share/smbusers/%u 
	default_shell = /bin/sh
  entry_negative_timeout = 0
  debug_level = 3
[pam]
  debug_level = 3
 
[domain/domain.com]
  debug_level = 3 
	ad_domain = DOMAIN.COM 
	krb5_realm = DOMAIN.COM
  enumerate = false 
	realmd_tags = manages-system joined-with-adcli 
	cache_credentials = True 
	id_provider = ad 
	krb5_store_password_if_offline = True 
	ldap_id_mapping = True 
	use_fully_qualified_names = False 
	fallback_homedir = /home/%d/%u 
	access_provider = simple
  auth_provider = ad 
	selinux_provider = False 
	ldap_referrals = false 
	ad_server = DC.DOMAIN.COM 
	ad_backup_server = DC1.DOMAIN.COM 
	ldap_sasl_mech = GSSAPI 
	ldap_schema = ad 
	lookup_family_order = ipv4_only 
	case_sensitive = false 
	ldap_user_search_base = dc=domain,dc=com 
	ldap_group_search_base = dc=domain,dc=com 
	ldap_access_order = expire 
	ldap_account_expire_policy = ad 
	ldap_force_upper_case_realm = true 
	krb5_canonicalize = false 
	ldap_user_object_class = user 
	ldap_user_name = sAMAccountName 
	ldap_user_gecos = displayName 
	ldap_user_principal = userPrincipalName 
	ldap_user_modify_timestamp = whenChanged 
	ldap_user_shadow_last_change = pwdLastSet 
	ldap_user_shadow_expire = accountExpires
	ldap_group_object_class = group
  default_shell = /bin/bash
  ldap_krb5_init_creds = true
```
### 12.4 nsswitch
> sudo nano /etc/nsswitch.conf 
```
(In the first three parameters passwd, group, shadow add winbind after files separated by a space)
```
### 12.5 Blocking USB 

> sudo systemctl start usbguard
> sudo systemctl status usbguard
> sudo systemctl enable usbguard

### 12.6 Customization samba (replace default values)
> sudo nano /etc/samba/smb.conf 
```
[global]
workgroup = DOMAIN
realm = DOMAIN.COM
security = ADS
encrypt passwords = true
dns proxy = no
socket options = TCP_NODELAY
domain master = no
local master = no
preferred master = no
os level = 0
domain logons = no
winbind refresh tickets = yes
idmap config * : range = 10000-20000
idmap config * : backend = tdb
winbind enum users = yes
winbind enum groups = yes
template homedir = /home/%D/%U
template shell = /usr/bin/zsh
client use spnego = yes
client ntlmv2 auth = yes
encrypt passwords = yes
winbind use default domain = yes
restrict anonymous = 2
load printers = no
show add printer wizard = no
printcap name = /dev/null
disable spoolss = yes
```
Reboot PC
## 13 Configuring the creation of a "profile" for each new user
> sudo nano /etc/security/pam_winbind.conf
```
debug=no
debug_state=no
try_first_pass=yes
krb5_auth=yes
krb5_cache_type=FILE
cached_login=yes
silent=no
mkhomedir=yes
```
## 14	sudo nano /etc/conf.d/samba
```
SAMBA_DAEMONS=(smbd nmbd)
SAMBA_DAEMONS=(smbd nmbd winbindd)
```
## 15 sudo nano /etc/hosts
We delete all references to IPv6 and write the fully qualified domain name of the machine + IPv4's address in the format.
[127.0.0.1] [pc.domain.com pc]

## 16 Checking the status of services smb, nmb and winbindd

> sudo systemctl status smb
> sudo systemctl status nmb
> sudo systemctl status winbind

Reboot PC
## 17 sudo nano /etc/pam.d/system-auth
```
#%PAM-1.0
auth [success=1 default=ignore] pam_localuser.so
auth [success=2 default=die] pam_winbind.so
auth [success=1 default=die] pam_unix.so nullok
auth requisite pam_deny.so
auth      optional  pam_permit.so
auth      required  pam_env.so

account   required  pam_unix.so
account [success=1 default=ignore] pam_localuser.so
account required pam_winbind.so
account   optional  pam_permit.so
account   required  pam_time.so

password [success=1 default=ignore] pam_localuser.so
password [success=2 default=die] pam_winbind.so
password [success=1 default=die] pam_unix.so sha512 shadow
password requisite pam_deny.so
password  optional  pam_permit.so

session   required  pam_limits.so
session   required  pam_unix.so
session required pam_mkhomedir.so umask=0022 skel=/etc/skel
session [success=1 default=ignore] pam_localuser.so
session required pam_winbind.so
session   optional  pam_permit.so
```
## 18 Checking the connection with the domain
kinit [admin_username]
klist
## 19 Add PC to the domain

> sudo net ads join -U [admin_username]

## 20 Add a user to the docker group

> sudo usermod -a -G docker [username]

Reboot PC
## 21 Starting services and adding to startup

> sudo systemctl start smb
> sudo systemctl start nmb
> sudo systemctl start winbind
> sudo systemctl status smb
> sudo systemctl status nmb
> sudo systemctl status winbind
> sudo systemctl enable smb
> sudo systemctl enable nmb
> sudo systemctl enable winbind

## 22 Downloading x11vnc

> sudo pacman -Syyuu x11vnc

## 23 Configurating x11vnc service
> sudo nano /etc/systemd/system/x11vnc.service
```
Description=VNC Server for X11
Requires=display-manager.service
After=display-manager.service
[Service]
Type=forking
ExecStart=/usr/bin/x11vnc -auth guess -norc -forever -shared -bg -rfbauth /etc/x11vnc.passwd -autoport 5900 -o /var/log/x11vnc.log -xkb –repeat -noxrecord -noxfixes -nomodtweak 
```
## 24	Configurating graphical.target
> sudo nano /etc/systemd/system/graphical.target

```
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
[Unit]
Description=Graphical Interface
Documentation=man:systemd.special(7)
Requires=multi-user.target
After=multi-user.target
Conflicts=rescue.target
Wants=display-manager.service
Wants=x11vnc.service
AllowIsolate=yes
[Install]
Alias=default.target
```
## 25 Password for VNC 

> x11vnc --storepasswd  /etc/x11vnc.passwd

## 26 Changing Desktop Manager

> sudo pacman -R sddm-kcm
> sudo pacman –R sddm
> sudo systemctl disable sddm
> sudo pacman –S lxdm
> sudo systemctl start lxdm
> sudo systemctl enable lxdm

## 27 FIX TROUBLES
## 27.1.1 Solving keyboard problems, in VNC - create fix.sh on your Desktop
```
#!/bin/sh
xmodmap -e "keycode 59 = 0x002c 0x003c 0x06c2 0x06e2"
xmodmap -e "keycode 60 = 0x002e 0x003e 0x06c0 0x06e0"
xmodmap -e "keycode 94 = 0x002c 0x003c 0x06c2 0x06e2"
 ```

### 27.1.2 Explaining to the user how to add a script to startup !ATTENTION! Do under user's account!
1. Launch StartMenu
2. Searching Autostart
3. Add Script
4. Choose desktop path => fix.sh
5. Ok

### 27.2 Solve the problem with tearings. autoload !ATTENTION! Do under user's account!
> Option 1
```
Use modesetting dirver (for newer GPUs intel's driver is integrated into the kernel)
# content as /etc/X11/xorg.conf.d/20-intel.conf :
for modesetting driver:
# THIS STEP ALSO SOLVED THE PROBLEM WITH TEARING!!
#this is to use the modesetting driver
#for the intel iGPU instead of the intel driver
Section "Device"
    Identifier "intel"
    Driver "modesetting"
    BusID "PCI:0:2:0"
EndSection
```

> Option 2.
```
1. Go to 'start'
2. Computer
3. System settings
4. Display and monitor.
5. Compositor
6. Rendering backend : XRender
7. Scale Method : Crisp
8. Apply!
```
### 27.3 (kde wallet disable)
```
sudo nano 
/home/DOMAIN/username/.config/kwalletrc
 Enabled=false
```
```
sudo kill kdewallet 
```
also we can install seahorse package and, its can help to see this package and remove wallet from system

### 27.4(pacman compression)
> sudo nano /etc/makepkg.conf
Replacing
```
compressxz=(xz -c -z - --threads=0)
compressgz=(pigz -c -f -n)
compressbz2=(pbzip2 -c -f)
compresszst=(zstd -c -z -q - --threads=0)
```
### 27.5 (swap+swapiness)
``` 
1. sudo nano /etc/sysctl.d/99-swappiness.conf
2. vm.swappiness=10
```
### 27.6 check the rules in PoliceKit pkg and Timeshift pkg.
### 27.7 When updating the OS, always make a timeshift slice, with cutoff date.
### 27.8 Required to use the UltraVNC client on the user's computer  (or Remmina in Linux)



