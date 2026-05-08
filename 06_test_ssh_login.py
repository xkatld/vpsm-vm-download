import subprocess

def test_ssh_login():
    result = subprocess.run(
        ["incus", "list", "status=running", "--format", "csv", "-c", "n,4"],
        capture_output=True,
        text=True
    )
    
    lines = [line.strip() for line in result.stdout.split("\n") if line.strip()]
    
    password = "vpsm.link"
    
    print(f"{'CONTAINER':<30} {'IP ADDRESS':<20} {'STATUS'}")
    print("-" * 65)

    for line in lines:
        parts = line.split(",")
        name = parts[0]
        ip = parts[1].split(" ")[0] if parts[1] else "No IP"
        
        if ip == "No IP":
            print(f"{name:<30} {ip:<20} [FAILED] No IP")
            continue

        cmd = [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            f"root@{ip}", "whoami"
        ]
        
        try:
            ssh_result = subprocess.run(cmd, capture_output=True, text=True)
            if ssh_result.returncode == 0:
                print(f"{name:<30} {ip:<20} [SUCCESS]")
            else:
                print(f"{name:<30} {ip:<20} [FAILED] {ssh_result.stderr.strip()}")
        except Exception as e:
            print(f"{name:<30} {ip:<20} [ERROR] {str(e)}")

if __name__ == "__main__":
    test_ssh_login()
