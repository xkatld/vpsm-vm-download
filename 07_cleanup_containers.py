import subprocess

def run_cmd(container, cmd):
    try:
        print(f"CLEANING: {container}")
        subprocess.run(["incus", "exec", container, "--", "sh", "-c", cmd], check=True)
    except subprocess.CalledProcessError:
        print(f"FAILED: {container}")

def cleanup_containers():
    result = subprocess.run(["incus", "list", "status=running", "--format", "csv", "-c", "n"], capture_output=True, text=True)
    containers = [line.strip() for line in result.stdout.split("\n") if line.strip()]

    common_cleanup = "rm -rf /tmp/* /var/tmp/* && rm -f /root/.bash_history /root/.ash_history /root/.zsh_history"

    for name in containers:
        if "alpine" in name:
            pkg_cleanup = "apk cache clean"
        elif "debian" in name or "ubuntu" in name:
            pkg_cleanup = "apt-get clean && rm -rf /var/lib/apt/lists/*"
        elif "almalinux" in name or "rockylinux" in name:
            pkg_cleanup = "dnf clean all && rm -rf /var/cache/dnf"
        else:
            pkg_cleanup = "true"

        run_cmd(name, f"{pkg_cleanup} && {common_cleanup}")

if __name__ == "__main__":
    cleanup_containers()
