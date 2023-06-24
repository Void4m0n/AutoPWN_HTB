# ACADEMY AUTPWN SCRIPT

## PREVIEW

![](./Stocker_Autopwn.gif)

## DESCRIPTION

This script will PWN Stocker automatically, just spawn the machine, exec the script and wait for the magic to happen.

## INSTALL

### DEBIAN BASED
```
wget https://github.com/Void4m0n/AutoPWN_HTB/raw/main/Stokcer/Stocker_Autopwn_Repo.zip
unzip Stocker_Autopwn_Repo.zip
cd Stocker 
pip3 install -r ./requirements.txt
```
## USAGE

```
python3 Stocker_Autopwn.py
```
## PWN SCHEME

- [1] Brute force subdomains.
- [2] Bypass login performing a NoSQLi.
- [3] Exploiting LFI injected via XSS into a PDF to extract:
	- [3.1] User angoose inside the /etc/passwd 
	- [3.2] Angoose credendital inside the /var/www/dev/index.js file
- [4] Login through SSH as angoose.
- [5] Get user.txt flag.
 -[6] Exploiting configuration vulnerability with sudo -l perm to privesc.
- [7] Extracting root.txt flag.

