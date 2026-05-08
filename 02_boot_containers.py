import subprocess
import os

def boot_containers():
    image_file = "/root/vpsm-lxc-download/镜像.md"
    if not os.path.exists(image_file):
        return

    variants = ["all", "lite"]
    
    version_map = {
        "debian": {
            "bullseye": "11",
            "bookworm": "12",
            "trixie": "13"
        },
        "ubuntu": {
            "jammy": "2204",
            "noble": "2404",
            "resolute": "2604"
        }
    }
    
    with open(image_file, "r") as f:
        lines = f.readlines()

    for line in lines[1:]:
        parts = line.strip().split("\t")
        if len(parts) < 3:
            continue
            
        distro = parts[0].strip()
        release = parts[1].strip()
        arch = parts[2].strip()
        
        image_alias = f"{distro}-{release}"
        
        display_release = release
        if distro in version_map and release in version_map[distro]:
            display_release = version_map[distro][release]
        
        for variant in variants:
            container_name = f"{distro}{display_release}-{variant}-arm64-lxc".replace(".", "")
            
            print(f"LAUNCHING: {container_name} from {image_alias}")
            try:
                subprocess.run(
                    ["incus", "launch", image_alias, container_name],
                    check=True
                )
            except subprocess.CalledProcessError:
                print(f"FAILED to launch: {container_name}")

if __name__ == "__main__":
    boot_containers()
