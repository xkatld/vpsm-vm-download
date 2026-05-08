import subprocess
import os

def export_images():
    project_dir = "/root/vpsm-vm-download"
    
    result = subprocess.run(
        ["incus", "image", "list", "--format", "csv", "-c", "L"],
        capture_output=True,
        text=True
    )
    
    aliases = [line.strip() for line in result.stdout.split("\n") if line.strip()]

    for alias in aliases:
        if "-all-" not in alias and "-lite-" not in alias:
            continue
            
        print(f"EXPORTING: {alias}")
        target_path = os.path.join(project_dir, alias)
        
        try:
            subprocess.run(
                ["incus", "image", "export", alias, target_path],
                check=True
            )
            print(f"SUCCESS: {alias} exported as {target_path}")
        except subprocess.CalledProcessError:
            print(f"FAILED: {alias}")

if __name__ == "__main__":
    export_images()
