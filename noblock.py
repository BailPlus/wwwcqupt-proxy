#Copyright Bail 2025
#wwwcqupt-proxy:noblock 阻塞自动重启 v1.0_1
#2025.6.14

import subprocess, time

process:subprocess.Popen | None = None

def is_blocked() -> bool:
    return subprocess.run(
        'ss | grep https | wc -l',
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip() != '0'

def restart_service():
    global process
    if process is not None:
        process.terminate()
    process = subprocess.Popen(
        ['python3', 'app.py']
    )

def main():
    restart_service()
    while True:
        if is_blocked():
            print("正在重启服务...")
            restart_service()
        else:
            print("服务正常运行")
        time.sleep(1800)

if __name__ == "__main__":
    main()
