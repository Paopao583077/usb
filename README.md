# USB设备指纹识别系统 - 使用指南

## 📋 系统概述

本系统基于USB通信流量的时间序列特征，为USB设备（特别是U盘）生成唯一的"指纹"，用于设备认证和身份识别。

### 核心功能

- ✅ **设备注册**: 为已知设备创建指纹并存入数据库
- ✅ **设备认证**: 验证未知设备是否为已注册的合法设备
- ✅ **自动采集**: 引导用户完成USB流量数据采集过程

---

## 🚀 快速开始

### 环境要求

- **操作系统**: Windows 10/11
- **Python**: 3.7+
- **依赖软件**: Wireshark (包含TShark)
- **Python库**: pyshark, numpy

### 安装依赖

```bash
pip install pyshark numpy
```

### 目录结构

```
usb/
├── Main.py                    # 主程序入口
├── AutoCatch.py               # 数据采集模块
├── Register.py                # 设备注册模块
├── Authenticate.py            # 设备认证模块
├── FeatureExtractor.py        # 特征提取引擎
├── usb_fingerprint_db.json    # 指纹数据库
└── devices/
    ├── enroll/                # 注册样本存放目录
    │   ├── capture_1.pcapng
    │   ├── capture_2.pcapng
    │   └── capture_3.pcapng
    └── auth/                  # 验证样本存放目录
        └── auth_verify.pcapng
```

---

## 📖 使用教程

### 运行主程序

```bash
python Main.py
```

系统会显示三种模式供选择：

```
【模式选择】
1. [设备注册] - 从现有采集文件生成指纹
2. [采集+注册] - 完整的新设备录入流程
3. [设备认证] - 验证未知设备身份
```

---

## 🔐 模式1: 设备注册

**适用场景**: 已有采集好的pcapng文件，直接生成指纹

### 操作步骤

1. **准备数据文件**
   - 将采集的 `.pcapng` 文件放入 `devices/enroll/` 目录
   - 建议至少3个样本文件以提高准确性

2. **运行注册**
   ```bash
   python Main.py
   ```
   - 选择模式 **1**
   - 输入设备名称（例如：`SanDisk_32G`）
   - 系统自动提取特征并注册

3. **查看结果**
   - 注册成功后，指纹保存在 `usb_fingerprint_db.json`
   - 可以查看枚举时间、传输特征等统计信息

### 示例输出

```
>>> 【模式1: 设备注册】
正在检查文件夹: d:\Project\usb\devices\enroll ...
[√] 发现 3 个数据样本。
请输入设备名称 (ID, 例如 SanDisk_32G): MyUSB

>>> 开始计算指纹特征 (设备ID: MyUSB) ...
[-] 正在聚合 3 个样本的特征...
    [调试] capture_1.pcapng: 枚举时间 = 0.2427s
    [调试] capture_2.pcapng: 枚举时间 = 0.0640s
    [调试] capture_3.pcapng: 枚举时间 = 0.0639s
    [√] 枚举指纹就绪: 均值 0.1235s
    [√] 传输指纹 (Endpoint=1): 均值 0.000673s
    [√] 传输指纹 (Endpoint=130): 均值 0.000890s
[成功] 设备 'MyUSB' 注册完成！数据库已更新。
```

---

## 🔄 模式2: 采集+注册

**适用场景**: 新U盘首次录入，需要完整的采集和注册流程

### 操作步骤

1. **启动流程**
   ```bash
   python Main.py
   ```
   - 选择模式 **2**

2. **配置参数**
   - 输入U盘盘符（例如：`E`）
   - 输入设备名称（例如：`Kingston_64G`）
   - 输入采集次数（建议：`3-5`）

3. **执行采集**（系统会循环执行以下步骤）
   - **拔出U盘** → 按Enter开始监听
   - **插入U盘** → 系统自动捕获枚举和传输数据
   - **采集完成** → 自动保存pcapng文件
   - 重复指定次数

4. **生成指纹**
   - 采集完成后，选择 `y` 立即注册
   - 系统自动聚合所有样本并生成指纹

### 注意事项

⚠️ **采集过程请注意**:
- 确保在提示时才插入/拔出U盘
- 等待I/O测试完成（50MB读写）
- 不要在采集过程中中断程序

---

## ✅ 模式3: 设备认证

**适用场景**: 验证未知U盘是否为已注册的合法设备

### 认证方式

#### 方式A: 从已有文件认证

**适用于**: 已有待验证的pcapng文件

1. 将验证文件放入 `devices/auth/` 目录
2. 运行 Main.py 选择模式 **3**
3. 选择方式 **A**
4. 选择是否指定设备ID（留空则与所有设备对比）
5. 查看认证结果

#### 方式B: 实时采集并认证

**适用于**: 现场验证U盘

1. 运行 Main.py 选择模式 **3**
2. 选择方式 **B**
3. 输入U盘盘符
4. 按提示插拔U盘（只需1次采集）
5. 查看认证结果

### 认证结果解读

```
[✓] 认证通过！
    匹配设备: SanDisk_32G
    相似度: 95.6%
    注册时间: 2026-01-11 21:23:35
    
建议操作: 允许该设备访问系统
```

**相似度阈值**: 默认70%
- **≥70%**: 认证通过，设备合法
- **<70%**: 认证失败，可能是未授权设备

### 认证原理

系统通过以下特征计算相似度：

1. **枚举特征** (权重30%)
   - USB设备枚举时间的统计特性
   - 反映设备与主机的协商速度

2. **传输特征** (权重70%)
   - 不同Endpoint的包间时间间隔
   - 反映设备控制器的时序特性

综合相似度 = 0.3 × 枚举相似度 + 0.7 × 传输相似度平均值

---

## 🔧 高级配置

### 修改配置参数

编辑 `Main.py` 中的全局配置：

```python
# 1. Wireshark TShark路径
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# 2. USBPcap接口（根据你的系统调整）
INTERFACE = "USBPcap3"

# 3. 数据存储路径
BASE_FOLDER = "devices"
DB_FILE = "usb_fingerprint_db.json"

# 4. 认证阈值（0-100）
AUTH_THRESHOLD = 70.0  # 可调整以改变严格程度
```

### 调整采集参数

编辑 `AutoCatch.py` 中的参数：

```python
target_size_mb=50  # 采集的数据量（MB）
```

---

## 📊 数据库格式

`usb_fingerprint_db.json` 存储所有已注册设备的指纹：

```json
{
  "SanDisk_32G": {
    "fingerprint": {
      "enumeration": {
        "mean": 0.1235,      // 枚举时间均值（秒）
        "std": 0.0843,       // 标准差
        "count": 3           // 样本数
      },
      "transfers": {
        "1": {               // Endpoint 1
          "mean": 0.000673,  // 传输时间均值（秒）
          "std": 0.001183,   // 标准差
          "count": 2320      // 样本数
        },
        "130": {             // Endpoint 130
          "mean": 0.000890,
          "std": 0.001474,
          "count": 1860
        }
      }
    },
    "reg_time": "2026-01-11 21:23:35",
    "samples_count": 3,
    "source_files": [
      "capture_1.pcapng",
      "capture_2.pcapng",
      "capture_3.pcapng"
    ]
  }
}
```

---

## 🛠️ 故障排除

### 常见问题

#### Q1: 找不到TShark

**错误信息**: `[错误] 找不到 Tshark: C:\Program Files\Wireshark\tshark.exe`

**解决方案**:
- 安装 [Wireshark](https://www.wireshark.org/download.html)
- 确认安装路径，修改 `Main.py` 中的 `TSHARK_PATH`

---

#### Q2: 未提取到特征

**现象**: 指纹数据库中 `enumeration: null, transfers: {}`

**可能原因**:
- pcapng文件中没有USB数据包
- USBPcap接口设置错误
- 采集时间太短，数据不足

**解决方案**:
- 检查 `INTERFACE` 设置（运行 `tshark -D` 查看可用接口）
- 增加采集时间或数据量
- 确保采集时U盘有读写活动

---

#### Q3: 认证相似度太低

**现象**: 相同U盘认证相似度<70%

**可能原因**:
- 采集环境差异（不同USB端口、系统负载）
- 样本数量太少
- U盘本身特性不稳定

**解决方案**:
- 增加注册样本数量（5-10个）
- 在相同环境下采集和认证
- 降低阈值（例如60%）

---

#### Q4: Windows asyncio错误

**错误信息**: `NotImplementedError: Subprocesses are not supported...`

**解决方案**: 代码已自动修复，使用 `WindowsProactorEventLoopPolicy`

---

## 📚 技术参考

### 特征提取算法

#### 枚举时间
- **定义**: 最后一批连续Control传输 → 第1个Bulk传输的时间差
- **典型值**: 50ms - 300ms
- **意义**: 反映USB设备与主机的协商速度

#### 传输时间
- **定义**: 相同Endpoint的连续USB包的时间间隔
- **典型值**: 0.0001s - 0.01s
- **意义**: 反映设备控制器的时序特性

### 相似度计算

使用归一化欧氏距离：

```python
similarity = 100 - (|mean1 - mean2| / avg_std) × 10
```

---

## 🎯 应用场景

### 企业安全
- **未授权设备检测**: 识别员工私自使用的U盘
- **设备白名单**: 只允许已注册的U盘访问系统
- **数据泄露防护**: 阻止未知U盘接入

### 取证分析
- **设备溯源**: 确认特定U盘是否连接过系统
- **时间线分析**: 结合采集时间戳建立事件序列

### 研究用途
- **USB设备特性研究**: 分析不同厂商/型号的时序差异
- **物理层指纹识别**: 探索硬件级别的设备识别方法

---

## 📝 开发说明

### 模块架构

```
Main.py          - 用户交互和流程控制
  ├── AutoCatch.py      - USB流量采集（调用TShark）
  ├── Register.py       - 指纹注册逻辑
  ├── Authenticate.py   - 指纹认证逻辑
  └── FeatureExtractor.py - 特征提取引擎
       └── pyshark      - pcapng文件解析
```

### 扩展开发

#### 添加新特征

在 `FeatureExtractor.py` 中扩展：

```python
# 示例：添加数据包大小分布特征
def extract_packet_size_distribution(cap):
    sizes = []
    for pkt in cap:
        if hasattr(pkt, 'usb'):
            sizes.append(int(pkt.length))
    return calculate_stats(sizes)
```

#### 自定义相似度算法

在 `Authenticate.py` 中修改：

```python
def calculate_similarity(feature1, feature2):
    # 使用马氏距离、余弦相似度等
    pass
```

---

## 📄 许可与贡献

本项目为学习研究用途，欢迎改进和扩展。

### 待实现功能

- [ ] GUI界面
- [ ] 实时监控模式（后台运行）
- [ ] 机器学习分类器（SVM/Random Forest）
- [ ] 配置文件支持（YAML）
- [ ] 日志系统

---

## 📞 支持

如有问题，请查看：
- `改进总结_USB指纹识别系统优化.md` - 详细的技术文档
- 项目源码注释

---

**最后更新**: 2026-01-12  
**版本**: 2.0  
**作者**: USB Fingerprint Team
