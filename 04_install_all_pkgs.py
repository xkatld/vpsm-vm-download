import subprocess

def run_cmd(container, cmd):
    try:
        print(f"RUNNING on {container}: {cmd}")
        subprocess.run(["incus", "exec", container, "--", "sh", "-c", cmd], check=True)
    except subprocess.CalledProcessError:
        print(f"FAILED on {container}")

def install_all_pkgs():
    result = subprocess.run(["incus", "list", "status=running", "--format", "csv", "-c", "n"], capture_output=True, text=True)
    containers = [line.strip() for line in result.stdout.split("\n") if line.strip()]

    pkgs_apt = "bash git unzip screen wget curl sudo nano"
    pkgs_apk = "bash git unzip screen wget curl sudo nano"
    pkgs_dnf = "bash git unzip screen wget curl sudo nano"

    for name in containers:
        if "-all-" not in name:
            continue
            
        print(f"INSTALLING PACKAGES: {name}")
        
        if "alpine" in name:
            run_cmd(name, f"apk add {pkgs_apk}")
        elif "debian" in name or "ubuntu" in name:
            run_cmd(name, f"apt update && apt install -y {pkgs_apt}")
        elif "almalinux" in name or "rockylinux" in name:
            enable_repo = "dnf install -y epel-release && dnf config-manager --set-enabled crb"
            run_cmd(name, f"{enable_repo} && dnf install -y {pkgs_dnf}")

if __name__ == "__main__":
    install_all_pkgs()
