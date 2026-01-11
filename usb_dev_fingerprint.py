"""
USB设备指纹识别系统 - 实时主动探测模式 (Active Probing)
功能：通过实时捕获USB流量并主动激励产生流量，提取时序特征进行设备身份认证

作者：基于原有离线PCAP模式重构
日期：2026-01-11
"""

import pyshark
import sys
import os
import json
import numpy as np
import threading
import ctypes
import time
import tempfile

# Windows 专用模块
try:
    import win32file
    import win32con
    import pywintypes
except ImportError:
    print("❌ 缺少 pywin32 模块，请运行: pip install pywin32")
    sys.exit(1)

# ========== 配置常量 ==========
REFERENCE_DB = "usb_device_fingerprint_high_res.json"
TSHARK_PATH = r"D:\UsefulTools\Wireshark\tshark.exe"
USBPCAP_INTERFACE = "USBPcap4"
SECTOR_SIZE = 4096  # 扇区大小，用于对齐
TRAFFIC_SIZE_MB = 50  # 流量激励大小 (MB)

# ========== 权限检查 ==========
def is_admin():
    """检查是否具有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ========== 基础工具 ==========
def load_db():
    if not os.path.exists(REFERENCE_DB):
        return {}
    try:
        with open(REFERENCE_DB, "r") as f:
            return json.load(f)
    except:
        return {}

def save_db(db):
    with open(REFERENCE_DB, "w") as f:
        json.dump(db, f, indent=4)

# ========== 特征键定义 ==========
FEATURE_KEYS = ["mean_latency", "std_latency", "min_latency", "p75_latency", 
                "mean_interval", "cv_interval", "mean_length"]

def vectorize(feat):
    return np.array([feat[k] for k in FEATURE_KEYS], dtype=float)

# ========== 实时捕获扫描器类 ==========
class LiveAuthScanner:
    """
    实时USB流量捕获与分析器
    使用 pyshark.LiveCapture 进行实时抓包
    """
    
    def __init__(self, interface=USBPCAP_INTERFACE):
        self.interface = interface
        self.tshark_path = TSHARK_PATH
        self.packets = []
        self.capture = None
        self.capture_thread = None
        self.stop_event = threading.Event()
        
        # 验证 tshark 存在
        if not os.path.exists(self.tshark_path):
            raise FileNotFoundError(f"❌ 未找到 tshark: {self.tshark_path}")
    
    def _capture_worker(self):
        """抓包线程工作函数"""
        try:
            self.capture = pyshark.LiveCapture(
                interface=self.interface,
                tshark_path=self.tshark_path,
                display_filter="usb.transfer_type == 0x02"  # Bulk传输
            )
            
            for packet in self.capture.sniff_continuously():
                if self.stop_event.is_set():
                    break
                self.packets.append(packet)
                
        except Exception as e:
            print(f"⚠ 抓包线程异常: {e}")
        finally:
            if self.capture:
                try:
                    self.capture.close()
                except:
                    pass
    
    def start_capture(self):
        """启动实时抓包线程"""
        self.packets = []
        self.stop_event.clear()
        self.capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
        self.capture_thread.start()
        print(f"🔄 抓包线程已启动 (接口: {self.interface})")
    
    def stop_capture(self):
        """停止抓包"""
        self.stop_event.set()
        
        # 强制关闭 capture 以中断 sniff_continuously
        if self.capture:
            try:
                self.capture.close()
            except:
                pass
        
        # 等待线程结束
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=3.0)
        
        print(f"⏹ 抓包已停止，共捕获 {len(self.packets)} 个数据包")
    
    def generate_traffic(self, drive_letter):
        """
        主动激励逻辑：向U盘写入并读取数据，绕过Windows缓存
        
        使用 FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH 确保
        数据真实经过USB总线而非从系统缓存读取
        """
        # 规范化盘符
        if not drive_letter.endswith(":"):
            drive_letter = drive_letter + ":"
        if not drive_letter.endswith("\\"):
            drive_path = drive_letter + "\\"
        else:
            drive_path = drive_letter
            
        # 生成临时文件路径
        temp_filename = f"usb_probe_{int(time.time())}.tmp"
        file_path = os.path.join(drive_path, temp_filename)
        
        # 计算对齐后的数据大小
        raw_size = TRAFFIC_SIZE_MB * 1024 * 1024
        aligned_size = (raw_size // SECTOR_SIZE) * SECTOR_SIZE
        
        print(f"📝 生成流量激励: {aligned_size // (1024*1024)}MB -> {file_path}")
        
        handle = None
        try:
            # 创建文件句柄，使用 NO_BUFFERING 绕过缓存
            handle = win32file.CreateFile(
                file_path,
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0,  # 不共享
                None,
                win32con.CREATE_ALWAYS,
                win32con.FILE_FLAG_NO_BUFFERING | win32con.FILE_FLAG_WRITE_THROUGH,
                None
            )
            
            # 生成随机数据并写入
            print("   ⬆ 写入数据...")
            data = os.urandom(aligned_size)
            win32file.WriteFile(handle, data)
            
            # 重置文件指针到开头
            win32file.SetFilePointer(handle, 0, win32con.FILE_BEGIN)
            
            # 读取数据
            print("   ⬇ 读取数据...")
            _, read_data = win32file.ReadFile(handle, aligned_size)
            
            # 验证数据完整性
            if read_data == data:
                print("   ✅ 数据完整性验证通过")
            else:
                print("   ⚠ 数据完整性验证失败")
            
        except pywintypes.error as e:
            print(f"   ❌ Win32 错误: {e}")
            raise
        finally:
            # 关闭句柄
            if handle:
                win32file.CloseHandle(handle)
            
            # 删除临时文件
            try:
                os.remove(file_path)
                print("   🗑 临时文件已删除")
            except:
                pass
        
        print("✅ 流量激励完成")
    
    def extract_features_from_packets(self):
        """从捕获的数据包中提取特征"""
        if len(self.packets) < 10:
            print(f"⚠ 捕获的数据包不足 ({len(self.packets)})")
            return None
        
        latencies = []
        packet_intervals = []
        lengths = []
        last_out_time = None
        last_pkt_time = None
        
        for pkt in self.packets:
            try:
                # 获取时间戳
                curr_time = float(pkt.sniff_time.timestamp())
                
                # 计算包间隔
                if last_pkt_time is not None:
                    packet_intervals.append(curr_time - last_pkt_time)
                last_pkt_time = curr_time
                
                # 获取传输方向
                if hasattr(pkt, 'usb'):
                    direction = getattr(pkt.usb, "endpoint_address_direction", None)
                    
                    if direction == '0':  # OUT
                        last_out_time = curr_time
                    elif direction == '1' and last_out_time is not None:  # IN
                        latency = curr_time - last_out_time
                        if 0 < latency < 0.1:  # 合理范围内
                            latencies.append(latency)
                        last_out_time = None
                    
                    # 获取数据长度
                    data_len = getattr(pkt.usb, "data_len", 0)
                    if data_len:
                        lengths.append(int(data_len))
                        
            except Exception as e:
                continue
        
        if len(latencies) < 10:
            print(f"⚠ 有效响应对不足 ({len(latencies)})")
            return None
        
        # 转换为numpy数组并去除异常值
        latencies = np.array(latencies)
        latencies = latencies[latencies < np.percentile(latencies, 90)]
        
        if len(latencies) < 5:
            print("⚠ 去噪后样本不足")
            return None
        
        # 计算特征
        features = {
            "mean_latency": float(np.mean(latencies)),
            "std_latency": float(np.std(latencies)),
            "min_latency": float(np.min(latencies)),
            "p75_latency": float(np.percentile(latencies, 75)),
            "mean_interval": float(np.mean(packet_intervals)) if packet_intervals else 0,
            "cv_interval": float(np.std(packet_intervals)/np.mean(packet_intervals)) if packet_intervals and np.mean(packet_intervals) > 0 else 0,
            "mean_length": float(np.mean(lengths)) if lengths else 0
        }
        
        print(f"📊 特征提取完成:")
        for k, v in features.items():
            print(f"   {k}: {v:.6f}")
        
        return features
    
    def auto_scan(self, drive_letter):
        """
        一键自动化流程:
        1. 启动抓包线程
        2. 延迟 0.5s 确保抓包就绪
        3. 执行流量激励
        4. 激励结束后停止抓包
        5. 提取并返回特征
        """
        print("\n" + "="*50)
        print("🚀 开始自动扫描流程")
        print("="*50)
        
        # Step 1: 启动抓包
        self.start_capture()
        
        # Step 2: 延迟等待抓包就绪
        print("⏳ 等待抓包就绪 (0.5s)...")
        time.sleep(0.5)
        
        # Step 3: 执行流量激励
        try:
            self.generate_traffic(drive_letter)
        except Exception as e:
            print(f"❌ 流量激励失败: {e}")
            self.stop_capture()
            return None
        
        # 额外等待确保所有包被捕获
        time.sleep(0.3)
        
        # Step 4: 停止抓包
        self.stop_capture()
        
        # Step 5: 提取特征
        features = self.extract_features_from_packets()
        
        return features


# ========== 建模逻辑 ==========
def build_model(samples):
    """构建设备身份模型"""
    X = np.array([vectorize(s) for s in samples])
    mean = np.mean(X, axis=0)
    raw_std = np.std(X, axis=0)
    
    # 自动平滑处理 - 防止标准差过小导致距离爆炸
    epsilons = np.array([
        1e-4,  # mean_latency
        1e-4,  # std_latency
        1e-4,  # min_latency
        1e-4,  # p75_latency
        0.05,  # mean_interval (加大到 50ms 容错)
        1.5,   # cv_interval (变异系数波动很大)
        50.0   # mean_length (长度波动 50 字节以内)
    ])
    
    smoothed_std = raw_std + epsilons
    
    return {
        "mean": mean.tolist(),
        "std": smoothed_std.tolist(),
        "is_model": True
    }


# ========== 认证逻辑 ==========
def authenticate(device_id, feature):
    """验证设备身份"""
    db = load_db()
    
    if device_id not in db:
        print(f"❌ 设备 '{device_id}' 未注册")
        return False
    
    if isinstance(db[device_id], list):
        print(f"❌ 设备 '{device_id}' 注册未完成")
        return False
    
    model = db[device_id]
    x = vectorize(feature)
    mean = np.array(model["mean"])
    std = np.array(model["std"])
    
    # 计算 z-score
    z_scores = (x - mean) / std
    dist = np.sqrt(np.sum(z_scores ** 2))
    
    # 打印偏差分析
    print(f"\n🔬 偏差分析 (平滑模式开启)")
    print(f"{'特征':<15} | {'偏差分量(z^2)':<15} | {'状态'}")
    print("-" * 50)
    for i, key in enumerate(FEATURE_KEYS):
        contrib = z_scores[i] ** 2
        status = "✅ 稳定" if contrib < 2.0 else "⚠️ 漂移"
        print(f"{key:<15} | {contrib:<15.4f} | {status}")
    
    print(f"\n📊 总距离 d = {dist:.4f} (阈值: 1.25)")
    
    if dist < 1.25:
        print("✅ 认证通过：物理指纹匹配。")
        return True
    else:
        print("❌ 认证失败：指纹差异过大。")
        return False


# ========== 自动化注册 ==========
def auto_enroll(device_id, drive_letter):
    """
    自动化注册流程:
    1. 自动循环执行 3 次流量采集
    2. 提取每次的特征
    3. 使用 build_model 建模并保存
    """
    print("\n" + "="*60)
    print(f"🔐 开始自动化注册: 设备ID = {device_id}")
    print(f"📀 目标盘符: {drive_letter}")
    print("="*60)
    
    # 检查是否已有模型
    db = load_db()
    if device_id in db and isinstance(db[device_id], dict) and db[device_id].get("is_model"):
        print(f"💡 设备 '{device_id}' 模型已存在，跳过注册。")
        print("   如需重新注册，请先删除现有模型。")
        return
    
    scanner = LiveAuthScanner()
    samples = []
    
    for i in range(3):
        print(f"\n{'─'*40}")
        print(f"📍 第 {i+1}/3 次采样")
        print(f"{'─'*40}")
        
        features = scanner.auto_scan(drive_letter)
        
        if features:
            samples.append(features)
            print(f"✔ 样本 {i+1} 采集成功")
        else:
            print(f"❌ 样本 {i+1} 采集失败")
            print("   请确保U盘已正确插入并可访问")
            return
        
        # 采样间隔
        if i < 2:
            print("\n⏳ 等待 2 秒后进行下一次采样...")
            time.sleep(2)
    
    # 建模
    print(f"\n{'─'*40}")
    print("🔧 正在构建设备身份模型...")
    print(f"{'─'*40}")
    
    model = build_model(samples)
    db[device_id] = model
    save_db(db)
    
    print("\n✨ 模型构建完成！")
    print(f"   设备ID: {device_id}")
    print(f"   特征均值: {model['mean']}")
    print(f"   已保存到: {REFERENCE_DB}")


# ========== 实时认证 ==========
def live_authenticate(device_id, drive_letter):
    """实时认证流程"""
    print("\n" + "="*60)
    print(f"🔑 开始实时认证: 设备ID = {device_id}")
    print("="*60)
    
    scanner = LiveAuthScanner()
    features = scanner.auto_scan(drive_letter)
    
    if features:
        return authenticate(device_id, features)
    else:
        print("❌ 特征提取失败，无法进行认证")
        return False


# ========== 主入口 ==========
def print_usage():
    print("""
USB设备指纹识别系统 - 实时主动探测模式
========================================

用法:
  python usb_dev_fingerprint.py enroll <设备ID> <盘符>
  python usb_dev_fingerprint.py auth <设备ID> <盘符>

参数:
  enroll  - 注册新设备 (自动采集3次样本并建模)
  auth    - 认证设备身份
  设备ID  - 自定义的设备标识符
  盘符    - U盘盘符 (如 E: 或 F:)

示例:
  python usb_dev_fingerprint.py enroll MyUSB E:
  python usb_dev_fingerprint.py auth MyUSB E:

注意:
  - 必须以管理员权限运行
  - 需要安装 USBPcap 并确保 USBPcap4 接口可用
  - 需要安装 pywin32: pip install pywin32
""")


if __name__ == "__main__":
    # 检查管理员权限
    if not is_admin():
        print("="*50)
        print("❌ 错误: 需要管理员权限！")
        print("="*50)
        print("\n请右键点击命令提示符或 PowerShell，")
        print("选择「以管理员身份运行」后重试。")
        print("\n原因: 实时调用 USBPcap 接口需要管理员权限")
        sys.exit(1)
    
    # 检查 tshark
    if not os.path.exists(TSHARK_PATH):
        print(f"❌ 未找到 tshark: {TSHARK_PATH}")
        print("请检查 Wireshark 安装路径")
        sys.exit(1)
    
    # 解析命令行参数
    if len(sys.argv) != 4:
        print_usage()
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    device_id = sys.argv[2]
    drive_letter = sys.argv[3]
    
    # 验证盘符格式
    if not drive_letter[0].isalpha():
        print(f"❌ 无效的盘符: {drive_letter}")
        sys.exit(1)
    
    # 执行对应模式
    if mode == "enroll":
        auto_enroll(device_id, drive_letter)
    elif mode == "auth":
        result = live_authenticate(device_id, drive_letter)
        sys.exit(0 if result else 1)
    else:
        print(f"❌ 未知模式: {mode}")
        print_usage()
        sys.exit(1)