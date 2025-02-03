import subprocess
import os

def run_scripts():
    subprocess.Popen(['wt', 'new-tab', 'python', 'api.py', ';', 'new-tab', 'python', 'app.py'], shell=True)

if __name__ == "__main__":
    run_scripts()