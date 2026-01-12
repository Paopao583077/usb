import os
import time
import subprocess
import sys


def run_single_capture(
        tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
        interface="USBPcap3",
        output_base_folder="devices",
        sub_folder="enroll",  # 子文件夹：enroll 或 auth
        file_name="capture.pcapng",
        target_size_mb=50,
        drive_letter="E"
):
    """
    执行【单次】抓包与USB流量读写测试（包含枚举阶段捕获）。

    参数:
    - sub_folder: 子文件夹名称，例如 "enroll" (注册用) 或 "auth" (验证用)
    - file_name: 保存的文件名
    """

    # --- 0. 环境检查与路径构建 ---
    if not os.path.exists(tshark_path):
        print(f"[严重错误] 找不到 tshark.exe: {tshark_path}")
        return False

    # 构建完整路径: devices/enroll/capture_1.pcapng
    base_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = os.path.join(base_dir, output_base_folder, sub_folder)
    full_save_path = os.path.join(target_dir, file_name)

    # 确保文件夹存在
    if not os.path.exists(target_dir):
        print(f"[-] 正在创建目录: {target_dir}")
        os.makedirs(target_dir, exist_ok=True)

    # 清理旧文件
    if os.path.exists(full_save_path):
        try:
            os.remove(full_save_path)
        except:
            pass

    # 确定盘符
    if drive_letter is None:
        print("[错误] 未指定盘符。")
        return False

    usb_file_path = f"{drive_letter}:\\traffic_test_temp.dat"

    # ================= 采集流程开始 =================
    print(f"\n--- 开始采集任务: {sub_folder}/{file_name} ---")

    # 1. 强制拔出检查
    print("Step 1: 请确保 U 盘【已拔出】。")
    input("        确认拔出后，按回车键开始抓包...")

    # 2. 启动 Tshark (捕获枚举)
    print(f"Step 2: 启动监听接口 {interface}...")
    capture_cmd = [tshark_path, '-i', interface, '-F', 'pcapng', '-w', full_save_path]
    proc = subprocess.Popen(capture_cmd, stderr=subprocess.PIPE)

    time.sleep(2)  # 等待引擎启动
    if proc.poll() is not None:
        print("[错误] Tshark 进程启动失败！")
        return False

    # 3. 提示插入
    print(f"Step 3: >>> 请现在插入 U 盘 ({drive_letter}盘) <<<")
    print("        正在捕获枚举数据 (等待 10 秒)...")
    time.sleep(10)

    # 4. 检测盘符上线
    if not os.path.exists(f"{drive_letter}:\\"):
        print(f"[错误] 超时未检测到盘符 {drive_letter}:，请确认U盘插入正确。")
        proc.terminate()
        return False

    try:
        # 5. 执行读写 (捕获传输特征)
        print(f"Step 4: 正在进行 I/O 测试 ({target_size_mb}MB)...", end='')

        chunk_size = 1024 * 1024
        chunk_data = os.urandom(chunk_size)

        # 写入
        with open(usb_file_path, 'wb') as f:
            for mb in range(target_size_mb):
                f.write(chunk_data)
                f.flush()
                os.fsync(f.fileno())

        # 稍作停顿
        time.sleep(0.5)

        # 删除
        if os.path.exists(usb_file_path):
            os.remove(usb_file_path)
        print(" 完成！")
        time.sleep(2)  # 确保删除指令被抓到

    except Exception as e:
        print(f"\n[异常] I/O 操作出错: {e}")
        proc.kill()
        return False

    # 6. 停止抓包
    print("Step 5: 停止抓包...")
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

    # 结果确认
    if os.path.exists(full_save_path):
        f_size = os.path.getsize(full_save_path) / (1024 * 1024)
        print(f"    [√] 文件已保存: {sub_folder}\\{file_name} ({f_size:.2f} MB)")
        return True
    else:
        print("    [!] 文件生成失败。")
        return False


if __name__ == "__main__":
    # 默认调试调用
    run_single_capture(sub_folder="debug_test", drive_letter="E")