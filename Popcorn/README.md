# POPCORN AUTPWN SCRIPT

## PREVIEW

![](./utils/Popcorn_Autopwn.gif)

## DESCRIPTION

This script will pwn Popcorn automatically, just spawn the machine, exec the script and wait for the magic to happen.

## INSTALL

### DEBIAN BASED
```
wget https://github.com/Void4m0n/AutoPWN_HTB/raw/main/Popcorn/Popcorn_Autopwn_Repo.zip
unzip Popcorn_Autopwn_Repo.zip
cd Popcorn
chmod +x ./setup.sh
./setup.sh
```
## USAGE

```
python3 Popcorn_Autopwn.py [LHOST] 
```
## PWN SCHEME

- [1] Ask the user to register, because the app uses capchat.
- [2] Login and upload a valid torrent file (utils/Payload.txt.torrent).
- [3] Upload a web shell bypassing the file upload measures.
- [4] Share the Privilege Escalation script with a python server. 
- [5] Make a request through the web shell downloading the exploit and achieving the execution.
- [6] The script will create a user with root privilege, the credentials are toor:toor.
- [7] Login as toor to get the flags.
