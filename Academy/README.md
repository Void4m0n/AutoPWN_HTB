# ACADEMY AUTPWN SCRIPT

## PREVIEW

![](./utils/Academy_Autopwn.gif)

## DESCRIPTION

This script will pwn Academy automatically, just spawn the machine, exec the script and wait for the magic to happen.

## INSTALL

### DEBIAN BASED
```
wget https://github.com/Void4m0n/AutoPWN_HTB/raw/main/Academy/Academy_Autopwn_Repo.zip
unzip Academy_Autopwn_Repo.zip
cd Academy
chmod +x ./setup.sh
./setup.sh
```
## USAGE

Rembember to add the following line to the /etc/hosts: `10.10.10.215 academy.htb dev-staging-01.academy.htb` 
```
python3 Academy_Autopwn.py
```
## PWN SCHEME

- [1] Register user as admin (Changing roleid value to 1).
- [2] Login into the admin panel and extracting subdomain leak.
- [3] Extract laravel APP_KEY to encode the payloads, and explotating the CVE-2018-15133.
    - [3.1] Exploit CVE-2018-15133 to extract users from the /etc/hosts
    - [3.2] Exploit CVE-2018-15133 to extract password inside the /var/www/html/academy/.env
- [4] "Bruteforcing" ssh with the users and credential found.
- [5] cry0l1t3 is part of adm group, extracting hexadecimal password leak inside /var/log/audit/audit.log.3 and deconding to plain text.
- [6] Login as mrb3n, sudo -l perm on composer bin.
- [7] Privesc through composer bin (https://gtfobins.github.io/gtfobins/composer/).
- [8] Extracting flags.
