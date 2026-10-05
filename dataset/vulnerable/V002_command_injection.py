import subprocess

def list_directory(directory):
    command = "ls -l " + directory
    return subprocess.run(command, shell=True, capture_output=True, text=True)