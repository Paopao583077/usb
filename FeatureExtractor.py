import pyshark
import numpy as np
from collections import defaultdict
import os
import sys
import asyncio

# --- [Windows 兼容性修复 1] ---
# 必须在导入 asyncio 后立即设置策略，解决 TShark 退出码问题
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# --- 全局算法配置 ---
FILTER_PERCENTILE = 5


def calculate_stats(data_list):
    """ 计算统计特征 (均值, 标准差) """
    if not data_list or len(data_list) < 1:  # 放宽到至少1个样本
        return None

    arr = np.array(data_list)
    
    # 对于小样本（<10个），不做过滤，保留所有数据
    if len(arr) < 10:
        clean_arr = arr
    else:
        # 大样本才应用百分位数过滤
        lower = np.percentile(arr, FILTER_PERCENTILE)
        upper = np.percentile(arr, 100 - FILTER_PERCENTILE)
        clean_arr = arr[(arr >= lower) & (arr <= upper)]
        if len(clean_arr) == 0: clean_arr = arr

    return {
        "mean": float(np.mean(clean_arr)),
        "std": float(np.std(clean_arr)),
        "count": len(clean_arr)
    }


def get_transfer_type_safe(pkt):
    """ 安全获取 transfer_type """
    if not hasattr(pkt, 'usb'): return None
    try:
        raw_val = pkt.usb.transfer_type
        s_val = str(raw_val).lower()
        # USB 传输类型规范: 0x00=Iso, 0x01=Interrupt, 0x02=Control, 0x03=Bulk
        if s_val in ['0x03', '0x3', '3']: return 'BULK'
        if s_val in ['0x02', '0x2', '2']: return 'CONTROL'
        if s_val in ['0x01', '0x1', '1']: return 'INTERRUPT'
        if s_val in ['0x00', '0x0', '0']: return 'ISOCHRONOUS'
        return s_val
    except:
        return None


def process_pcap_file(pcap_path):
    """ 解析单个 pcap 文件 """
    if not os.path.exists(pcap_path): return None, None

    print(f"[-] 正在分析特征: {os.path.basename(pcap_path)} ...")

    # --- [关键修复 2] 暴力重建 Event Loop ---
    # 无论之前发生了什么，每次解析文件前都强行创建一个新的 Loop
    # 这样可以完美解决 "no running event loop" 问题
    new_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(new_loop)

    cap = None
    try:
        # keep_packets=False 防止内存爆炸
        # eventloop=new_loop 显式指定我们刚创建的 loop
        cap = pyshark.FileCapture(pcap_path, keep_packets=False, eventloop=new_loop)

        enum_start_time = None
        enum_end_time = None
        enum_val = None

        transfer_raw_data = defaultdict(list)
        pending_requests = {}


        packet_index = 0
        bulk_count = 0
        submit_count = 0
        complete_count = 0
        matched_count = 0


        for pkt in cap:
            packet_index += 1

            if not hasattr(pkt, 'usb'): continue

            t_type = get_transfer_type_safe(pkt)
            
            try:
                timestamp = float(pkt.sniff_timestamp)
            except:
                continue

            # 策略：找到紧邻Bulk包之前的最后一批Control传输
            # 1. 追踪Control包序列
            if t_type == 'CONTROL':
                if enum_end_time is None:  # 还没遇到Bulk包
                    # 如果上一个也是Control，继续；否则重新开始计时
                    if enum_start_time is None or (timestamp - enum_start_time) > 2.0:
                        # 开始新的Control包序列
                        enum_start_time = timestamp

            # 2. 遇到第1个Bulk包时，计算枚举时间
            elif t_type == 'BULK' and enum_end_time is None:
                enum_end_time = timestamp
                if enum_start_time:
                    duration = enum_end_time - enum_start_time
                    # 合理的枚举时间应该在0.01秒到2秒之间
                    if 0.01 < duration < 2.0:
                        enum_val = duration




            # 3. 提取传输数据 - 简化方法：使用包间时间间隔
            if t_type == 'BULK':
                bulk_count += 1
                try:
                    timestamp = float(pkt.sniff_timestamp)
                    endpoint = getattr(pkt.usb, 'endpoint_address', None)
                    
                    if endpoint:
                        # 计算与上一个相同endpoint的包的时间差
                        if endpoint in pending_requests:
                            last_time = pending_requests[endpoint]
                            delta = timestamp - last_time
                            
                            # 使用endpoint作为"长度"分组
                            if delta > 0 and delta < 1.0:  # 过滤掉异常大的间隔
                                matched_count += 1
                                transfer_raw_data[int(endpoint, 16) if isinstance(endpoint, str) else endpoint].append(delta)
                        
                        pending_requests[endpoint] = timestamp
                except Exception as e:
                    continue



        cap.close()
        print(f"    [调试] 总包数: {packet_index}, 枚举时间: {enum_val}, 传输分组数: {len(transfer_raw_data)}")
        print(f"    [调试] Bulk包: {bulk_count}, Submit: {submit_count}, Complete: {complete_count}, 匹配: {matched_count}")
        if enum_start_time and enum_end_time and not enum_val:
            actual_duration = enum_end_time - enum_start_time
            print(f"    [调试] 枚举时间被过滤: {actual_duration:.4f}s (范围: 0.01-2.0s)")
        if transfer_raw_data:
            for length, times in list(transfer_raw_data.items())[:3]:
                print(f"    [调试] 长度{length}: {len(times)}个样本")
        return enum_val, transfer_raw_data




    except Exception as e:
        import traceback
        print(f"    [!] 解析出错: {e}")
        print(f"    [!] 详细信息:\n{traceback.format_exc()}")
        if cap:
            try:
                cap.close()
            except:
                pass
        return None, None
    finally:
        # 清理 Loop
        try:
            if new_loop and not new_loop.is_closed():
                new_loop.close()
        except:
            pass