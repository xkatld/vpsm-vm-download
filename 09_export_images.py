import subprocess
import os

def export_images():
    # 获取项目目录
    project_dir = "/root/vpsm-lxc-download"
    
    # 获取所有带别名的本地镜像
    result = subprocess.run(
        ["incus", "image", "list", "--format", "csv", "-c", "L"],
        capture_output=True,
        text=True
    )
    
    # 过滤空行并获取别名
    aliases = [line.strip() for line in result.stdout.split("\n") if line.strip()]

    for alias in aliases:
        # 仅导出包含自建标签的镜像
        if "-all-" not in alias and "-lite-" not in alias:
            continue
            
        print(f"EXPORTING: {alias}")
        target_path = os.path.join(project_dir, alias)
        
        try:
            # 执行导出
            subprocess.run(
                ["incus", "image", "export", alias, target_path],
                check=True
            )
            print(f"SUCCESS: {alias} exported as {target_path}")
        except subprocess.CalledProcessError:
            print(f"FAILED: {alias}")

if __name__ == "__main__":
    export_images()
