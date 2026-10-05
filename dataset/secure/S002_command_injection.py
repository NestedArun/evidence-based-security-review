import subprocess

def list_directory(directory):
    return subprocess.run(
        ["ls", "-l", directory],
        capture_output=True,
        text=True,
        shell=False
    )