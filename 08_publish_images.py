import subprocess

def publish_images():
    result = subprocess.run(
        ["incus", "list", "--format", "csv", "-c", "n,s"],
        capture_output=True,
        text=True
    )
    lines = [line.strip() for line in result.stdout.split("\n") if line.strip()]

    for line in lines:
        parts = line.split(",")
        name = parts[0]
        status = parts[1]

        if status == "RUNNING":
            print(f"STOPPING: {name}")
            subprocess.run(["incus", "stop", name, "--force"], check=True)

        print(f"PUBLISHING: {name}")
        try:
            subprocess.run(
                ["incus", "publish", name, "--alias", name],
                check=True
            )
            print(f"SUCCESS: {name} published as image")
        except subprocess.CalledProcessError:
            print(f"FAILED: {name}")

if __name__ == "__main__":
    publish_images()
