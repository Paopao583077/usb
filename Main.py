import AutoCatch
import Register
import Authenticate  # 导入认证模块
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

# 4. 认证阈值配置
AUTH_THRESHOLD = 70.0  # 相似度阈值（0-100），超过此值认为匹配成功


# ===========================================

def main():
    print("=" * 60)
    print("      USB 设备指纹识别系统 (Main Controller)")
    print(f"      当前接口: {INTERFACE}")
    print("=" * 60)

    # 0. 基础环境检查
    if not os.path.exists(TSHARK_PATH):
        print(f"[错误] 找不到 Tshark: {TSHARK_PATH}")
        return

    # 构建文件夹绝对路径
    base_dir = os.path.dirname(os.path.abspath(__file__))
    enroll_path = os.path.join(base_dir, BASE_FOLDER, "enroll")
    auth_path = os.path.join(base_dir, BASE_FOLDER, "auth")

    print("-" * 60)
    print("【模式选择】")
    print("1. [设备注册] - 从现有采集文件生成指纹")
    print("   适用于: 已有 devices/enroll/*.pcapng 文件")
    print("")
    print("2. [采集+注册] - 完整的新设备录入流程")
    print("   适用于: 新U盘首次录入")
    print("   流程: 引导插拔采集 → 自动生成指纹")
    print("")
    print("3. [设备认证] - 验证未知设备身份")
    print("   适用于: 验证U盘是否为已注册设备")
    print("   流程: 从 devices/auth/*.pcapng 提取特征 → 匹配数据库")
    print("-" * 60)

    mode = input("请选择模式 (1/2/3): ").strip()

    # ================= 模式 1: 直接从文件注册 =================
    if mode == '1':
        print(f"\n>>> 【模式1: 设备注册】")
        print(f"正在检查文件夹: {enroll_path} ...")

        if not os.path.exists(enroll_path):
            print("[错误] 文件夹不存在，请先采集数据。")
            return

        files = [f for f in os.listdir(enroll_path) if f.endswith(".pcapng")]
        if not files:
            print("[错误] 文件夹为空，没有找到 .pcapng 文件。")
            print(f"提示: 请将采集的pcapng文件放入 {enroll_path}")
            return

        print(f"[√] 发现 {len(files)} 个数据样本。")
        device_name = input("请输入设备名称 (ID, 例如 SanDisk_32G): ").strip()
        if not device_name:
            print("[取消] 未输入设备名称。")
            return

        # 调用注册接口
        success = Register.run_registration(
            device_id=device_name,
            enroll_folder=enroll_path,
            db_file=DB_FILE
        )

        if success:
            print(f"\n提示: 设备 '{device_name}' 已成功注册到数据库！")
            print(f"      可以使用模式3进行设备认证测试。")

    # ================= 模式 2: 采集 + 注册 =================
    elif mode == '2':
        print(f"\n>>> 【模式2: 采集+注册】")
        print("\n=== 步骤 1/2: 数据采集 ===")
        
        user_drive = input("请输入目标 U 盘盘符 (例如 E): ").strip().upper()
        if not user_drive:
            print("[取消] 未输入盘符。")
            return

        device_name = input("请输入设备名称 (ID): ").strip()
        if not device_name:
            print("[取消] 未输入设备名称。")
            return

        try:
            count = int(input("请输入采集次数 (建议 3-5 次): "))
            if count < 1 or count > 10:
                print("采集次数设置为默认值 3")
                count = 3
        except:
            count = 3

        # 循环调用 AutoCatch
        for i in range(1, count + 1):
            print(f"\n--- 采集进度: {i}/{count} ---")
            success = AutoCatch.run_single_capture(
                tshark_path=TSHARK_PATH,
                interface=INTERFACE,
                output_base_folder=BASE_FOLDER,
                sub_folder="enroll",  # 存入注册文件夹
                file_name=f"capture_{i}.pcapng",
                target_size_mb=50,
                drive_letter=user_drive
            )
            # 如果某次采集失败，询问是否继续
            if not success:
                retry = input("采集出错。是否终止流程? (y/n): ")
                if retry.lower() == 'y':
                    print("[终止] 用户取消流程。")
                    return

        print("\n=== 步骤 2/2: 生成指纹 ===")
        do_reg = input("采集完成，是否立即注册? (y/n): ").lower()

        if do_reg == 'y':
            success = Register.run_registration(
                device_id=device_name,
                enroll_folder=enroll_path,
                db_file=DB_FILE
            )
            if success:
                print(f"\n提示: 新设备 '{device_name}' 录入成功！")
        else:
            print("已保存采集文件到 devices/enroll/，稍后可用模式1注册。")

    # ================= 模式 3: 设备认证 =================
    elif mode == '3':
        print(f"\n>>> 【模式3: 设备认证】")
        
        # 检查数据库是否存在
        if not os.path.exists(DB_FILE):
            print("[错误] 指纹数据库不存在，请先使用模式1或2注册设备。")
            return
        
        # 选择认证方式
        print("\n认证方式:")
        print("A. 从已有文件认证 (使用 devices/auth/*.pcapng)")
        print("B. 实时采集并认证 (需要插拔U盘)")
        
        auth_mode = input("请选择 (A/B): ").strip().upper()
        
        if auth_mode == 'A':
            # 从现有文件认证
            if not os.path.exists(auth_path):
                print(f"[错误] 认证文件夹不存在: {auth_path}")
                print(f"提示: 请将待验证的pcapng文件放入该文件夹")
                return
            
            files = [f for f in os.listdir(auth_path) if f.endswith(".pcapng")]
            if not files:
                print(f"[错误] {auth_path} 中没有 .pcapng 文件。")
                return
            
            print(f"[√] 发现 {len(files)} 个验证样本。")
            
        elif auth_mode == 'B':
            # 实时采集
            print("\n=== 实时采集验证数据 ===")
            user_drive = input("请输入 U 盘盘符 (例如 E): ").strip().upper()
            if not user_drive:
                print("[取消] 未输入盘符。")
                return
            
            print("提示: 建议采集 1-2 次即可")
            count = 1  # 认证只需要少量样本
            
            success = AutoCatch.run_single_capture(
                tshark_path=TSHARK_PATH,
                interface=INTERFACE,
                output_base_folder=BASE_FOLDER,
                sub_folder="auth",  # 存入认证文件夹
                file_name=f"auth_verify.pcapng",
                target_size_mb=50,
                drive_letter=user_drive
            )
            
            if not success:
                print("[错误] 采集失败，无法继续认证。")
                return
        else:
            print("[错误] 无效的选项。")
            return
        
        # 执行认证
        print("\n" + "=" * 60)
        device_id = input("指定要验证的设备ID (留空则与所有设备比对): ").strip()
        if not device_id:
            device_id = None
        
        passed, match_id, score = Authenticate.authenticate_device(
            auth_folder=auth_path,
            db_file=DB_FILE,
            device_id=device_id,
            threshold=AUTH_THRESHOLD
        )
        
        # 显示建议操作
        if passed:
            print("\n建议操作: 允许该设备访问系统")
        else:
            print("\n建议操作: 阻止该设备，可能是未授权设备")

    else:
        print("[错误] 无效选项，请选择 1、2 或 3。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[中断] 用户取消操作。")
        sys.exit(0)
