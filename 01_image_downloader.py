import subprocess
import os

def download_images():
    image_file = "/root/vpsm-lxc-download/镜像.md"
    if not os.path.exists(image_file):
        return

    with open(image_file, "r") as f:
        lines = f.readlines()

    for line in lines[1:]:
        parts = line.strip().split("\t")
        if len(parts) < 3:
            continue
            
        distro = parts[0].strip()
        release = parts[1].strip()
        arch = parts[2].strip()
        
        remote_path = f"images:{distro}/{release}/{arch}"
        alias = f"{distro}-{release}"
        
        print(f"IMPORTING: {remote_path}")
        try:
            subprocess.run(
                ["incus", "image", "copy", remote_path, "local:", "--alias", alias, "--quiet"],
                check=True
            )
        except subprocess.CalledProcessError:
            print(f"FAILED: {remote_path}")

if __name__ == "__main__":
    download_images()
