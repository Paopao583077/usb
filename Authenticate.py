import json
import os
import numpy as np
import FeatureExtractor
from collections import defaultdict


def calculate_similarity(feature1, feature2):
    """
    计算两个特征的相似度（改进算法 - 更严格的区分度）
    
    返回相似度分数 (0-100)，越高越相似
    
    改进点：
    1. 增加相对差异判断（百分比差异）
    2. 提高归一化差异的惩罚系数
    3. 添加变异系数检查（数据质量评估）
    4. 采用更严格的评分策略（取最小值）
    """
    if not feature1 or not feature2:
        return 0.0
    
    mean1 = feature1['mean']
    mean2 = feature2['mean']
    std1 = feature1['std']
    std2 = feature2['std']
    
    # 1. 计算绝对差异
    abs_diff = abs(mean1 - mean2)
    
    # 2. 计算相对差异（百分比）
    mean_avg = (mean1 + mean2) / 2
    if mean_avg == 0:
        return 0.0
    
    relative_diff_ratio = abs_diff / mean_avg
    
    # 3. 计算归一化差异（标准差归一化）
    std_avg = (std1 + std2) / 2
    if std_avg == 0:
        std_avg = 0.001
    
    normalized_diff = abs_diff / std_avg
    
    # 4. 相对差异得分
    # 20%差异 → 60分，50%差异 → 0分
    # 这样可以防止均值差距大的设备被误判为相似
    relative_score = max(0, 100 - relative_diff_ratio * 200)
    
    # 5. 归一化差异得分
    # 提高惩罚系数从10到20，使评分更严格
    normalized_score = max(0, 100 - normalized_diff * 20)
    
    # 6. 取较严格的分数（两个条件都要满足）
    # 这确保了即使一个条件通过，另一个不通过也会被拒绝
    similarity = min(relative_score, normalized_score)
    
    # 7. 变异系数检查（数据质量评估）
    # CV = std / mean，表示数据的波动程度
    cv1 = std1 / mean1 if mean1 > 0 else 0
    cv2 = std2 / mean2 if mean2 > 0 else 0
    cv_avg = (cv1 + cv2) / 2
    
    # 如果变异系数过大（>1.5），说明数据不稳定，降低可信度
    if cv_avg > 1.5:
        similarity *= 0.8  # 降低20%相似度
    
    return similarity


def authenticate_device(auth_folder, db_file, device_id=None, threshold=70.0):
    """
    [接口函数] 执行设备认证流程
    
    参数:
    - auth_folder: 存放验证用 .pcapng 文件的文件夹路径
    - db_file: 指纹数据库文件路径
    - device_id: 要验证的设备ID（None则与所有已注册设备对比）
    - threshold: 相似度阈值（0-100），超过此值认为匹配成功
    
    返回:
    - tuple: (是否通过, 匹配的设备ID, 相似度分数)
    """
    print(f"\n>>> 开始设备认证流程 ...")
    
    # 1. 检查验证数据文件
    if not os.path.exists(auth_folder):
        print(f"[错误] 找不到验证数据文件夹: {auth_folder}")
        return False, None, 0.0
    
    files = [f for f in os.listdir(auth_folder) if f.endswith(".pcapng")]
    if not files:
        print(f"[错误] {auth_folder} 中没有 pcapng 文件。")
        return False, None, 0.0
    
    print(f"[-] 正在分析验证样本 ({len(files)} 个文件)...")
    
    # 2. 提取验证样本的特征
    all_enum_times = []
    all_transfer_data = defaultdict(list)
    
    for f in files:
        path = os.path.join(auth_folder, f)
        e_time, t_data = FeatureExtractor.process_pcap_file(path)
        
        if e_time:
            all_enum_times.append(e_time)
        
        if t_data:
            for length, times in t_data.items():
                all_transfer_data[length].extend(times)
    
    # 3. 构建验证指纹
    auth_fingerprint = {}
    
    # 枚举指纹
    enum_stats = FeatureExtractor.calculate_stats(all_enum_times)
    if enum_stats:
        auth_fingerprint["enumeration"] = enum_stats
        print(f"    [√] 验证样本枚举特征: 均值 {enum_stats['mean']:.4f}s")
    else:
        print("    [!] 警告: 未提取到枚举时间特征。")
        auth_fingerprint["enumeration"] = None
    
    # 传输指纹 (取 Top 3)
    auth_fingerprint["transfers"] = {}
    sorted_lens = sorted(all_transfer_data.items(), key=lambda x: len(x[1]), reverse=True)[:3]
    
    for length, times in sorted_lens:
        stats = FeatureExtractor.calculate_stats(times)
        if stats:
            auth_fingerprint["transfers"][str(length)] = stats
            print(f"    [√] 验证样本传输特征 (Endpoint={length}): 均值 {stats['mean']:.6f}s")
    
    if not auth_fingerprint["enumeration"] and not auth_fingerprint["transfers"]:
        print("[错误] 未能提取到任何有效特征！")
        return False, None, 0.0
    
    # 4. 加载指纹数据库
    if not os.path.exists(db_file):
        print(f"[错误] 数据库文件不存在: {db_file}")
        return False, None, 0.0
    
    try:
        with open(db_file, 'r') as f:
            db = json.load(f)
    except Exception as e:
        print(f"[错误] 读取数据库失败: {e}")
        return False, None, 0.0
    
    if not db:
        print("[错误] 数据库为空，请先注册设备。")
        return False, None, 0.0
    
    # 5. 执行匹配
    print(f"\n[-] 正在与数据库中的设备指纹进行匹配 (阈值: {threshold})...")
    
    best_match_id = None
    best_score = 0.0
    match_details = {}
    
    # 确定要比对的设备列表
    if device_id:
        if device_id not in db:
            print(f"[错误] 设备 '{device_id}' 不在数据库中。")
            return False, None, 0.0
        compare_list = {device_id: db[device_id]}
    else:
        compare_list = db
    
    # 逐个设备比对
    for dev_id, dev_data in compare_list.items():
        print(f"\n  检查设备: {dev_id}")
        registered_fp = dev_data.get("fingerprint", {})
        
        # 计算枚举特征相似度
        enum_sim = 0.0
        if auth_fingerprint["enumeration"] and registered_fp.get("enumeration"):
            enum_sim = calculate_similarity(
                auth_fingerprint["enumeration"],
                registered_fp["enumeration"]
            )
            print(f"    - 枚举特征相似度: {enum_sim:.1f}%")
        
        # 计算传输特征相似度
        transfer_sims = []
        auth_transfers = auth_fingerprint.get("transfers", {})
        reg_transfers = registered_fp.get("transfers", {})
        
        # 找到共同的endpoint
        common_endpoints = set(auth_transfers.keys()) & set(reg_transfers.keys())
        
        if common_endpoints:
            for ep in common_endpoints:
                sim = calculate_similarity(auth_transfers[ep], reg_transfers[ep])
                transfer_sims.append(sim)
                print(f"    - 传输特征 Endpoint {ep} 相似度: {sim:.1f}%")
        
        # 计算综合相似度
        # 权重: 枚举特征30%，传输特征70%
        if enum_sim > 0 and transfer_sims:
            overall_sim = 0.3 * enum_sim + 0.7 * np.mean(transfer_sims)
        elif enum_sim > 0:
            overall_sim = enum_sim
        elif transfer_sims:
            overall_sim = np.mean(transfer_sims)
        else:
            overall_sim = 0.0
        
        print(f"    => 综合相似度: {overall_sim:.1f}%")
        
        match_details[dev_id] = {
            "enum_similarity": enum_sim,
            "transfer_similarities": transfer_sims,
            "overall_similarity": overall_sim
        }
        
        # 更新最佳匹配
        if overall_sim > best_score:
            best_score = overall_sim
            best_match_id = dev_id
    
    # 6. 判定结果
    print("\n" + "=" * 60)
    if best_score >= threshold:
        print(f"[✓] 认证通过！")
        print(f"    匹配设备: {best_match_id}")
        print(f"    相似度: {best_score:.1f}%")
        print(f"    注册时间: {db[best_match_id].get('reg_time', 'N/A')}")
        print("=" * 60)
        return True, best_match_id, best_score
    else:
        print(f"[✗] 认证失败！")
        if best_match_id:
            print(f"    最接近的设备: {best_match_id}")
            print(f"    相似度: {best_score:.1f}% (未达到阈值 {threshold}%)")
        else:
            print(f"    未找到匹配的设备")
        print("=" * 60)
        return False, best_match_id, best_score


if __name__ == "__main__":
    # 测试代码
    result = authenticate_device(
        auth_folder="devices/auth",
        db_file="usb_fingerprint_db.json",
        device_id=None,  # 与所有设备比对
        threshold=70.0
    )
    
    print(f"\n测试结果: {result}")
