import subprocess

def create_readme():
    result = subprocess.run(
        ["incus", "list", "status=running", "--format", "csv", "-c", "n"],
        capture_output=True,
        text=True
    )
    containers = [line.strip() for line in result.stdout.split("\n") if line.strip()]

    content = "本系统为vpsm.link构建,本文件无实际作用可随意处理。"

    for name in containers:
        print(f"CREATING README: {name}")
        try:
            subprocess.run(
                ["incus", "exec", name, "--", "sh", "-c", f'echo "{content}" > /root/README.md'],
                check=True
            )
        except subprocess.CalledProcessError:
            print(f"FAILED: {name}")

if __name__ == "__main__":
    create_readme()
