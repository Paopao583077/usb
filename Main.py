import AutoCatch
import Register  # 导入我们封装好的注册模块接口
import os
import sys

# ================= 全局配置 =================
# 1. Wireshark Tshark 路径
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# 2. 【关键】已验证的正确接口 (根据你刚才的测试结果)
INTERFACE = "USBPcap3"

# 3. 数据存储配置
BASE_FOLDER = "devices"
DB_FILE = "usb_fingerprint_db.json"


# ===========================================

def main():
    print("=" * 60)
    print("      USB 设备指纹注册系统 (Main Controller)")
    print(f"      当前接口: {INTERFACE}")
    print("=" * 60)

    # 0. 基础环境检查
    if not os.path.exists(TSHARK_PATH):
        print(f"[错误] 找不到 Tshark: {TSHARK_PATH}")
        return

    # 构建 enroll 文件夹绝对路径
    enroll_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), BASE_FOLDER, "enroll")

    print("-" * 60)
    print("1. [直接注册] (从现有文件生成指纹)")
    print("   - 适用于: 你已经手动采集好了 pcapng 文件")
    print("   - 操作: 直接读取 devices/enroll/ 下的文件进行计算")
    print("2. [全新注册] (采集 + 注册)")
    print("   - 适用于: 新设备首次录入")
    print("   - 操作: 引导你进行 3-5 次插拔采集，然后自动注册")
    print("-" * 60)

    mode = '1'  # 自动选择模式2
    # input("请选择模式 (1/2): ").strip()

    # ================= 模式 1: 直接从文件注册 =================
    if mode == '1':
        print(f"\n>>> 正在检查文件夹: {enroll_path} ...")

        if not os.path.exists(enroll_path):
            print("[错误] 文件夹不存在，请先采集数据。")
            return

        files = [f for f in os.listdir(enroll_path) if f.endswith(".pcapng")]
        if not files:
            print("[错误] 文件夹为空，没有找到 .pcapng 文件。")
            return

        print(f"[√] 发现 {len(files)} 个数据样本。")
        device_name = "zw"  # 自动使用设备名zw
        print(f"[自动模式] 设备名称: {device_name}")

        # 调用注册接口
        Register.run_registration(
            device_id=device_name,
            enroll_folder=enroll_path,
            db_file=DB_FILE
        )

    # ================= 模式 2: 采集 + 注册 =================
    elif mode == '2':
        print("\n=== 步骤 1/2: 数据采集 ===")
        user_drive = "E"  # 自动使用E盘
        if not user_drive: return

        device_name = "zw"  # 自动使用设备名zw
        if not device_name: return

        try:
            count = 3
        except:
            count = 3

        # 循环调用 Auto_Catch
        for i in range(1, count + 1):
            print(f"\n--- 采集进度: {i}/{count} ---")
            success = AutoCatch.run_single_capture(
                tshark_path=TSHARK_PATH,
                interface=INTERFACE,  # 使用正确的 USBPcap3
                output_base_folder=BASE_FOLDER,
                sub_folder="enroll",  # 存入注册文件夹
                file_name=f"capture_{i}.pcapng",
                target_size_mb=50,  # 50MB 保证有足够的 Bulk 数据
                drive_letter=user_drive
            )
            # 如果某次采集失败，询问是否继续
            if not success:
                retry = input("采集出错。是否终止流程? (y/n): ")
                if retry.lower() == 'y': return

        print("\n=== 步骤 2/2: 生成指纹 ===")
        do_reg = 'y'  # 自动选择注册

        if do_reg == 'y':
            Register.run_registration(
                device_id=device_name,
                enroll_folder=enroll_path,
                db_file=DB_FILE
            )
        else:
            print("已保存文件，未注册。")

    else:
        print("无效选项。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)