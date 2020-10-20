# check-list-manjaro
# Скачивание Manjaro Linux KDE Minimal

## 1. Запись установочного ISO на USB накопитель с помощью Rufus
## 2. Установка
### 2.1 Задать имя учётки localadm и пароль.
### 2.2 Задать имя машины 
###### MAC адрес смотрим в консоли (F12) командой ip addr.
###### Выбираем часовой пояс (Кишинёв)
## 3.	Подготовка удалённого доступа к машине
```
sudo systemctl start sshd
sudo systemctl status sshd (Проверяем статус службы)
sudo systemctl enable sshd
```
## 4.	Добавляем сертификат на рабочий стол (WinSCP)
```
sudo cp certificatename.crt /etc/ca-certificates/trust-source/anchors/
sudo trust extract-compat
```
## 5.   Устанавливаем yay и обновляем OS
```
sudo pacman –Syyuu yay
yay -Syyuu --nodiffmenu --nocleanmenu --noconfirm
```

## 6. Скачиваем из гитхаба софт для пользователей

### 6.1 Клонируем репозиторий
```
git clone https://github.com/alliedium/awesome-linux-config.git
```
### 6.2 Заходим в папку проекта
```
cd awesome-linux-config/manjaro19/basic/
```
### 6.3 Запускаем общесистемные скрипты установки.
```
./install_all.sh
```
## 7. Переходим в папку sysadmin и выполняем требуемые инструкции.
## 8. Перезагружаем ПК
## 9.	Понижаем версию ядра
```
sudo mhwd-kernel –I linux54
```
### 9.1 Перезагружаем систему
### 9.2 В процессе перезагрузки жмём Esc 
### 9.3 В открывшемся меню выбираем версию ядра 5.4 и загружаемся с нее
### 9.4 Удаляем более новое ядро
```
Sudo mhwd-kernel –r linux
```
## 10.	Проверяем обновления
```
yay -Syyuu --nodiffmenu --nocleanmenu --noconfirm
```
## 11.	Устанавливаем необходимый софт для ввода машины в домен (будет перенесено в папку sysadmin)
```
yay –Syyuu samba krb5 sssd tree usbguard kmplayer mplayer pam-krb5 ntp --nodiffmenu --nocleanmenu --noconfirm
```
## 12.	Перезагружаемм систему
## 13.	Проверяем текщее время на машине 
```
date
```
## 14.	Конфигурируем систему.
### 14.1 Настройка времени
> sudo nano /etc/ntp.conf  
###### Меняем IP и FQDN адреса NTP серверов на требуемые локальные
```
server 192.168.*.* 
server 192.168.*.*
server dc.server.com 
server dc1.server.com 
```

> sudo ntpd server 192.168.*.*

### 14.2 Настройка krb5 (изменить дефолтные значения на требуемые)

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
### 14.3 Настройка sssd (изменить дефолтные значения на требуемые)

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
### 14.4 nsswitch
> sudo nano /etc/nsswitch.conf 
```
(В первые три параметра passwd, group, shadow через пробел добавляем winbind после files)
```
### 14.5 блокируем USB
```
sudo systemctl start usbguard
sudo systemctl status usbguard
sudo systemctl enable usbguard
```
### 14.6 настройка samba (заменить дефолтные значения)
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
## 15.	Перезагрузка системы
## 16.	Настраиваем создание "профиля" для каждого нового пользователя
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
## 17.	Sudo nano /etc/conf.d/samba
```
SAMBA_DAEMONS=(smbd nmbd)
SAMBA_DAEMONS=(smbd nmbd winbindd)
```
## 18.	Sudo nano /etc/hosts
##### Удаляем все упоминания IPv6 и пишем полное доменное имя машины + её IPv4 адрес в формате.
##### 127.0.0.1 pc.domain.com pc

## 19.	Проверяем состояние служб smb, nmb и winbindd
```
sudo systemctl status smb
sudo systemctl status nmb
sudo systemctl status winbind
```
## 20.	Перезагрузка системы
## 21.	sudo nano /etc/pam.d/system-auth
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
## 22. Проверяем связь с доменом
##### kinit admin_user
##### klist
## 23.	Вводим машину в домен.
```
sudo net ads join -U [admin_user]
```
## 24.	Добавляем пользователя в группу docker
```
sudo usermod -a -G docker [ad_username]
```
## 25.	REBOOT
## 26.	Включаем службы и добавляем в автозагрузку
```
sudo systemctl start smb
sudo systemctl start nmb
sudo systemctl start winbind
sudo systemctl status smb
sudo systemctl status nmb
sudo systemctl status winbind
sudo systemctl enable smb
sudo systemctl enable nmb
sudo systemctl enable winbind
```
## 27.	Скачиваем x11vnc
```
sudo pacman -Syyuu x11vnc
```
## 28.	Конфижим x11vnc
> sudo nano /etc/systemd/system/x11vnc.service
```
Description=VNC Server for X11
Requires=display-manager.service
After=display-manager.service
[Service]
Type=forking
ExecStart=/usr/bin/x11vnc -auth guess -norc -forever -shared -bg -rfbauth /etc/x11vnc.passwd -autoport 5900 -o /var/log/x11vnc.log -xkb –repeat -noxrecord -noxfixes -nomodtweak 
```
## 29.	Конфижим graphical.target
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
## 30.	Пароль для VNC (в /bin/bash)
```
x11vnc --storepasswd  /etc/x11vnc.passwd
```
## 31.	Меняем DM
```
sudo pacman -R sddm-kcm
sudo pacman –R sddm
sudo systemctl disable sddm
sudo pacman –S lxdm
sudo systemctl start lxdm
sudo systemctl enable lxdm
```
## 32. Фиксирование проблем
##№ 32.1	Скидываем файл fix.sh (WinSCP) (решение проблем с клавиатурой, в VNC).
```

```
### 32.2	Обьясняем пользователю как добавить скрипт в автозагрузку !ВНИМАНИЕ! Делать из под учётки пользователя!
1. Пуск
2. Поиск Autostart
3. Add Script
4. Choose desktop path => fix.sh
5. OK
### 32.3.	Решаем проблему с разрывами. автозагрузку !ВНИМАНИЕ! Делать из под учётки пользователя!
> вариант 1. (проверить).
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
> вариант 2.
```
1. Зайти в пуск
2. Computer
3. System settings
4. Display and monitor.
5. Compositor
6. Rendering backend : XRender
7. Scale Method : Crisp
8. Apply!
```
### 32.4 (kde wallet disable)
```
sudo nano 
/home/DOMAIN/username/.config/kwalletrc
 Enabled=false
```
```
sudo kill kdewallet 
```
### 32.5 (pacman compression)
### 32.6 (swap+swapiness)
### 32.7 (проверить правила в PoliceKit) Veyon и Timeshift. (при обновлении ос, всегда делать срез таймшифтом, с указанием даты среза).

## 33.  АНТИВИРУС???? (WinSCP)
Sophos-av (free)

