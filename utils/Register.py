import json
import os
import time
from utils import FeatureExtractor
from collections import defaultdict


def run_registration(device_id, enroll_folder, db_file):
    """
    [接口函数] 执行设备注册流程

    参数:
    - device_id: 设备名称/ID (作为数据库的主键)
    - enroll_folder: 存放 .pcapng 文件的文件夹路径
    - db_file: 指纹数据库的保存路径 (.json)

    返回:
    - bool: 成功返回 True, 失败返回 False
    """
    print(f"\n>>> 开始计算指纹特征 (设备ID: {device_id}) ...")

    # 1. 检查数据文件
    if not os.path.exists(enroll_folder):
        print(f"[错误] 找不到数据文件夹: {enroll_folder}")
        return False

    files = [f for f in os.listdir(enroll_folder) if f.endswith(".pcapng")]
    if not files:
        print(f"[错误] {enroll_folder} 中没有 pcapng 文件，无法注册。")
        return False

    print(f"[-] 正在聚合 {len(files)} 个样本的特征...")

    # 2. 聚合所有样本的数据
    all_enum_times = []
    all_transfer_data = defaultdict(list)

    for f in files:
        path = os.path.join(enroll_folder, f)
        # 调用 FeatureExtractor
        e_time, t_data = FeatureExtractor.process_pcap_file(path)

        if e_time:
            all_enum_times.append(e_time)
            print(f"    [调试] {f}: 枚举时间 = {e_time:.4f}s")
        else:
            print(f"    [调试] {f}: 无枚举时间")

        if t_data:
            for length, times in t_data.items():
                all_transfer_data[length].extend(times)

    # 3. 构建指纹结构
    fingerprint = {}

    # --- A. 枚举指纹 (Enumeration Time) ---
    # 对应论文: 提取枚举时间序列 [cite: 35, 46]
    print(f"    [调试] 收集到的枚举时间样本: {all_enum_times}")
    enum_stats = FeatureExtractor.calculate_stats(all_enum_times)
    if enum_stats:
        fingerprint["enumeration"] = enum_stats
        print(f"    [√] 枚举指纹就绪: 均值 {enum_stats['mean']:.4f}s")
    else:
        print("    [!] 警告: 未提取到有效的枚举时间 (可能采集时未包含插入动作)。")
        fingerprint["enumeration"] = None

    # --- B. 传输指纹 (Transfer Time) ---
    # 对应论文: 按长度分组，取 Top 3 [cite: 50, 171]
    fingerprint["transfers"] = {}

    # 排序：按样本数量降序，取前 3 名
    sorted_lens = sorted(all_transfer_data.items(), key=lambda x: len(x[1]), reverse=True)[:3]

    if not sorted_lens:
        print("    [!] 警告: 未提取到有效的传输/读写数据。")

    for length, times in sorted_lens:
        stats = FeatureExtractor.calculate_stats(times)
        if stats:
            fingerprint["transfers"][str(length)] = stats
            print(f"    [√] 传输指纹 (Len={length}): 均值 {stats['mean']:.6f}s")

    # 4. 存入数据库
    # 确保目录存在
    db_dir = os.path.dirname(os.path.abspath(db_file))
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)

    # 读取旧数据
    try:
        if os.path.exists(db_file):
            with open(db_file, 'r') as f:
                db = json.load(f)
        else:
            db = {}
    except:
        db = {}

    # 更新条目
    db[device_id] = {
        "fingerprint": fingerprint,
        "reg_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "samples_count": len(files),
        "source_files": files
    }

    # 写入
    with open(db_file, 'w') as f:
        json.dump(db, f, indent=4)

    print(f"[成功] 设备 '{device_id}' 注册完成！数据库已更新。")
    return True