import subprocess

def run_cmd(container, cmd):
    try:
        subprocess.run(["incus", "exec", container, "--", "sh", "-c", cmd], check=True)
    except subprocess.CalledProcessError:
        print(f"FAILED: {container} -> {cmd}")

def setup_containers():
    result = subprocess.run(["incus", "list", "status=running", "--format", "csv", "-c", "n"], capture_output=True, text=True)
    containers = [line.strip() for line in result.stdout.split("\n") if line.strip()]

    for name in containers:
        print(f"CONFIGURING: {name}")
        
        run_cmd(name, "echo 'root:vpsm.link' | chpasswd")
        
        if "alpine" in name:
            update_cmd = "apk update && apk add openssh"
            ssh_config = "sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config"
            ssh_start = "rc-update add sshd && rc-service sshd restart"
            run_cmd(name, f"{update_cmd} && {ssh_config} && {ssh_start}")
            
        elif "debian" in name or "ubuntu" in name:
            update_cmd = "apt update && apt install -y openssh-server"
            ssh_config = "sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config"
            ssh_start = "service ssh restart || systemctl restart ssh"
            run_cmd(name, f"{update_cmd} && {ssh_config} && {ssh_start}")
            
        elif "almalinux" in name or "rockylinux" in name:
            pkg_mgr = "dnf" if ("10" in name or "9" in name or "8" in name) else "yum"
            update_cmd = f"{pkg_mgr} makecache && {pkg_mgr} install -y openssh-server"
            ssh_config = "sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config"
            ssh_start = "ssh-keygen -A && systemctl enable sshd && systemctl restart sshd"
            run_cmd(name, f"{update_cmd} && {ssh_config} && {ssh_start}")

if __name__ == "__main__":
    setup_containers()
