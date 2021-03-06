# check-list-manjaro
## Downloading  Manjaro Linux KDE Minimal [1]
## Downloading Rufus [2]

# ATTENTION!  Do not work as root

## 1. Burning the installation ISO to the USB storage device with Rufus
## 2. Installation
### 2.1 Set the username and password 
### 2.2 Set hostname
```
(hostname is compilation from 2 letters country name, + mac address pc)
The MAC address you'll see in the console (F12) with command ip addr | grep -E ether
```
### 2.3 Set timezone [3]
```
command in terminal tzselect
```
## 3.	Preparing remote access to the machine
```
sudo systemctl start sshd
sudo systemctl status sshd
sudo systemctl enable sshd
```

## 4.	Adding the network certificate to the desktop (with help USB, or SCP, for Linux remote system, or WinSCP for Windows remote system) 
```
sudo cp certificatename.crt /etc/ca-certificates/trust-source/anchors/
sudo trust extract-compat
```
## 5.   Installing  yay and updating OS
```
sudo pacman -Syyuu yay
yay -Syyuu --nodiffmenu --nocleanmenu --noconfirm
```
## 6 Downloading software for users from Alliedium project repository

### 6.1 Cloning the repository

> git clone https://github.com/alliedium/awesome-linux-config.git

### 6.2 Go to the project folder

> cd awesome-linux-config/manjaro/basic/

### 6.3 Running the system-wide installation scripts from sudousers member (but not root).

> ./install_all.sh

## 7. Change directory to the sysadmin folder and follow the instructions from her.
```
cd awesome-linux-config/manjaro/basic/sysadmin
./change_to_zsh.sh
cat checlist.md (and follow instructions)
```
 Reboot PC
## 8. Downgrading the kernel version (sic!) to the current LTS version [4]

> sudo mhwd-kernel –I linux54

 Reboot PC
 ```
In time reboot we must press Esc 
In the menu that opens, select the kernel version LTS (5.4 for now), and boot from it
Removing the newer kernel
```

> sudo mhwd-kernel –r linux59 
```
Remove new kernel - linux59 for now, also we can install and remove kernels from GUI in menu "Kernel"
```

## 9. Install system updates

> yay -Syyuu --nodiffmenu --nocleanmenu --noconfirm
> sudo systemctl enable fstrim.timer

## 10. Installing software for adding host to Active Directory domain [5]

> sudo pacman -S  krb5 usbguard pam-krb5

 Reboot PC
## 11.	Checking current time && configuring time services on the system. [6]

> timedatectl
 
### 11.1 Check and correct time settings
```
sudo systemctl status ntpd (must be dead)
sudo systemctl status systemd-timesyncd 
sudo systemctl start systemd-timesync 
sudo systemctl enable systemd-timesync 
```
## 11.1.1 Change servers to our local time servers, then restart the service
Determine ntp servers
```
(ntp server -  is your domain controller server. To find domain controller IP execute the command bellow: 
```
> grep "nameserver" /etc/resolv.conf

Then go to the time service config
> sudo nano /etc/systemd/timesyncd.conf

Change the default addresses to  our local NTP addresses (found above)
```
[Time]
NTP=0.arch.pool.ntp.org 
FallbackNTP=1.pool.ntp.org 
```
## 11.1.2 Checking time settings
```
 timedatectl show-timesync --all
 timedatectl set-ntp true 
 timedatectl timesync-status
```
### 12.2 Customization krb5 (change the default values to the required ones) [7]

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

### 12.4 nsswitch [9]
> sudo nano /etc/nsswitch.conf 
```
(In the first three parameters passwd, group, shadow add winbind after files separated by a space)
```
### 12.5 Blocking USB [10]
```
sudo systemctl start usbguard
sudo systemctl status usbguard
sudo systemctl enable usbguard
```
### 12.6 Customization samba (replace default values) [11]
> sudo nano /etc/samba/smb.conf 
```
[global]
workgroup = DOMAIN
realm = DOMAIN.COM
security = ADS
dns proxy = no
socket options = TCP_NODELAY
domain master = no
local master = no
preferred master = no
os level = 0
winbind refresh tickets = yes
idmap config * : range = 10000-20000
idmap config * : backend = tdb
winbind enum users = yes
winbind enum groups = yes
template homedir = /home/%D/%U
template shell = /usr/bin/zsh
winbind use default domain = yes
restrict anonymous = 2
load printers = no
show add printer wizard = no
printcap name = /dev/null
disable spoolss = yes
```
Reboot PC
## 13 Configuring the creation of a "profile" for each new user [12]
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

## 15 sudo nano /etc/hosts
We delete all references to IPv6 and write the fully qualified domain name of the machine + IPv4's address in the format.
[127.0.0.1] [pc.domain.com pc]

## 16 Checking the status of services smb, nmb and winbindd
```
sudo systemctl status smb
sudo systemctl status nmb
sudo systemctl status winbind
```
Reboot PC
## 17 sudo nano /etc/pam.d/system-auth [13]
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
```
> sudo systemctl start smb
> sudo systemctl start nmb
> sudo systemctl start winbind
> sudo systemctl status smb
> sudo systemctl status nmb
> sudo systemctl status winbind
> sudo systemctl enable smb
> sudo systemctl enable nmb
> sudo systemctl enable winbind
```

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
```
> sudo pacman -R sddm-kcm
> sudo pacman –R sddm
> sudo systemctl disable sddm
> sudo pacman –S lxdm
> sudo systemctl start lxdm
> sudo systemctl enable lxdm
```

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
```
sudo nano /etc/makepkg.conf
```

Replacing
```
compressxz=(xz -c -z - --threads=0)
compressgz=(pigz -c -f -n)
compressbz2=(bzip2 -c -f)
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
-----------------------------------------------------------------------------------------------
```
[1] https://manjaro.org/downloads/official/kde/
[2] https://github.com/pbatard/rufus/releases/download/v3.13/rufus-3.13.exe
[3] https://man.archlinux.org/man/tzselect.8.en
[4] https://wiki.manjaro.org/index.php/Manjaro_Kernels
[5] https://wiki.archlinux.org/index.php/Active_Directory_integration
[5] https://www.redhat.com/sysadmin/linux-active-directory
[6] https://wiki.archlinux.org/index.php/systemd-timesyncd
[7] https://wiki.archlinux.org/index.php/Kerberos
[7] https://docs.oracle.com/cd/E26502_01/html/E29042/krb5.conf-4.html
[7] https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html#appdefaults
[8] https://man.archlinux.org/man/nsswitch.conf.5.en
[9] https://wiki.archlinux.org/index.php/USBGuard
[10] https://wiki.archlinux.org/index.php/samba
[11] https://man.archlinux.org/man/pam_winbind.8.en
[12] https://wiki.archlinux.org/index.php/PAM

```
