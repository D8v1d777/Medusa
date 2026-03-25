import os
import base64
import urllib.parse
from string import Template
from typing import List, Dict

class ReverseShellGenerator:
    """
    Sovereign Reverse Shell Generation Engine.
    Derived from high-performance payloads for rapid offensive deployment.
    """
    def __init__(self):
        self.package_dir = os.path.dirname(os.path.abspath(__file__))
        # We'll use the commands from the repo we just cloned for now
        self.commands_dir = os.path.join(self.package_dir, "revshellgen_repo", "commands")
        
        if not os.path.exists(self.commands_dir):
            # Fallback if the repo isn't there (should not happen in this workflow)
            os.makedirs(self.commands_dir, exist_ok=True)
            
        self.shells = ['/bin/sh', '/bin/bash', '/bin/zsh', '/bin/ksh', '/bin/tcsh', '/bin/dash']
        self.cached_commands = sorted([c for c in os.listdir(self.commands_dir) if os.path.isfile(os.path.join(self.commands_dir, c))])

    def list_commands(self) -> List[str]:
        return self.cached_commands

    def generate(self, ip: str, port: str, command_name: str, shell: str = '/bin/bash', encode: str = 'none') -> str:
        """Generates the weaponized payload."""
        command_path = os.path.join(self.commands_dir, command_name)
        if not os.path.exists(command_path):
            return f"Error: Command {command_name} not found."

        with open(command_path, 'r') as f:
            template_content = f.read()

        # Handle specific cases where shell isn't needed or should be fixed
        if command_name in ('windows_powershell', 'unix_bash', 'unix_telnet', 'unix_awk'):
             # These templates might already define their shell or don't use it
             pass

        t = Template(template_content)
        payload = t.safe_substitute(ip=ip, port=port, shell=shell)

        if encode.lower() == 'url':
            payload = urllib.parse.quote_plus(payload)
        elif encode.lower() == 'base64':
            payload = base64.b64encode(payload.encode()).decode()

        return payload

    def save_to_downloads(self, payload: str, filename: str):
        """Saves the payload to the Windows Downloads folder."""
        downloads_path = os.path.join(os.environ['USERPROFILE'], 'Downloads')
        file_path = os.path.join(downloads_path, filename)
        
        with open(file_path, 'w') as f:
            f.write(payload)
        return file_path

def run_test():
    gen = ReverseShellGenerator()
    print("[*] Available Commands:", gen.list_commands())
    print("[*] Testing Bash Reverse Shell Save...")
    payload = gen.generate("127.0.0.1", "4444", "unix_bash")
    file_path = gen.save_to_downloads(payload, "medusa_rev_shell.txt")
    print(f"[+] Payload stored at: {file_path}")

if __name__ == "__main__":
    run_test()
