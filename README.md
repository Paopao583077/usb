# USB设备指纹识别系统 - 使用指南

## 📋 系统概述

本系统基于USB通信流量的时间序列特征，为USB设备（特别是U盘）生成唯一的"指纹"，用于设备认证和身份识别。

### ✨ 核心功能

- ✅ **图形界面**: 美观直观的GUI操作界面（推荐使用）
- ✅ **设备注册**: 为已知设备创建指纹并存入数据库
- ✅ **设备认证**: 验证未知设备是否为已注册的合法设备
- ✅ **自动采集**: 引导用户完成USB流量数据采集过程
- ✅ **数据库管理**: 查看、删除已注册设备
- ✅ **配置管理**: 图形化配置系统参数

---

## 🚀 快速开始

### 环境要求

- **操作系统**: Windows 10/11
- **Python**: 3.7+
- **依赖软件**: Wireshark (包含TShark)
- **Python库**: pyshark, numpy, ttkbootstrap

### 安装依赖

```bash
pip install pyshark numpy ttkbootstrap
```

### 启动程序

**推荐方式 - GUI界面**:
```bash
python Main_GUI.py
```

**传统方式 - 命令行**:
```bash
python Main.py
```

### 项目结构

```
usb/
├── Main_GUI.py                # 🎯 GUI主程序（推荐使用）
├── Main.py                    # CLI主程序（备用）
├── gui_utils.py               # GUI辅助工具模块
├── config.json                # 系统配置文件
├── AutoCatch.py               # 数据采集模块
├── Register.py                # 设备注册模块
├── Authenticate.py            # 设备认证模块
├── FeatureExtractor.py        # 特征提取引擎
├── usb_fingerprint_db.json    # 指纹数据库
└── devices/
    ├── enroll/                # 注册样本存放目录（注册后自动清空）
    └── auth/                  # 验证样本存放目录
```

---

## �️ GUI界面使用教程（推荐）

### 启动GUI

```bash
python Main_GUI.py
```

### 界面概览

GUI界面包含四个主要功能标签页：

#### � 设备注册
两种注册方式可选：

1. **从文件注册**
   - 适用于已有 `.pcapng` 文件的情况
   - 选择文件夹路径：`devices/enroll/`
   - 输入设备名称（如：`SanDisk_32G`）
   - 点击"开始注册"

2. **采集+注册**
   - 适用于新U盘首次录入
   - 输入U盘盘符（如：`E`）
   - 输入设备名称
   - 设置采集次数（建议3-5次）
   - 点击"开始采集"
   - 按对话框提示插拔U盘
   - 自动完成注册

#### 🔍 设备认证
两种认证方式可选：

1. **从文件认证**
   - 选择包含验证数据的文件夹
   - 可选指定目标设备ID
   - 调整相似度阈值（0-100，默认70）
   - 查看认证结果

2. **实时采集认证**
   - 输入U盘盘符
   - 按提示插拔U盘
   - 实时查看认证结果

**认证结果显示**：
- ✅ **绿色 - 认证通过**: 设备匹配成功，显示设备ID和相似度
- ❌ **红色 - 认证失败**: 未找到匹配或相似度过低

#### 💾 数据库管理
- 查看所有已注册设备列表
- 显示设备ID、注册时间、样本数量
- 刷新列表
- 删除选中设备

#### ⚙ 系统配置
可配置项：
- **TShark路径**: Wireshark TShark程序位置
- **USB接口**: USBPcap捕获接口（如：USBPcap3）
- **数据根目录**: 样本文件存储位置
- **数据库文件**: 指纹数据库路径

配置修改后点击"保存配置"即可生效。

### 系统日志窗口

底部日志窗口实时显示：
- 操作进度提示
- 特征提取详情
- 错误和警告信息
- 采集引导提示

### 注意事项

⚠️ **采集过程中的对话框交互**：
- 系统会弹出确认对话框，提示插拔U盘
- 点击"确定"继续，点击"取消"中止操作
- 注意按对话框提示操作，不要提前插拔U盘

✅ **注册后自动清理**：
- 每次注册成功后，`devices/enroll/` 文件夹会自动清空
- 避免不同设备样本互相覆盖
- 下次注册时从干净状态开始

---

## 📖 CLI命令行使用（备用）

如果需要使用命令行界面：

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

### 模式1: 设备注册

1. 将 `.pcapng` 文件放入 `devices/enroll/`
2. 选择模式 **1**
3. 输入设备名称
4. 系统自动提取特征并注册

### 模式2: 采集+注册

1. 选择模式 **2**
2. 输入U盘盘符、设备名称、采集次数
3. 按提示插拔U盘完成采集
4. 选择是否立即注册

### 模式3: 设备认证

**方式A**: 从已有文件认证
- 将验证文件放入 `devices/auth/`
- 选择方式 **A**

**方式B**: 实时采集并认证
- 选择方式 **B**
- 按提示插拔U盘

---

## 🔐 认证原理

### 特征提取

系统提取两类时序特征：

1. **枚举特征** (权重30%)
   - USB设备枚举阶段的时间统计
   - 反映设备与主机的协商速度
   - 典型值：50ms - 300ms

2. **传输特征** (权重70%)
   - 不同Endpoint的包间时间间隔
   - 反映设备控制器的时序特性
   - 典型值：0.0001s - 0.01s

### 相似度计算

使用归一化欧氏距离：

```
similarity = 100 - (|mean1 - mean2| / avg_std) × 10
综合相似度 = 0.3 × 枚举相似度 + 0.7 × 传输相似度平均值
```

### 认证判定

- **≥70%**: 认证通过，设备合法 ✅
- **<70%**: 认证失败，可能是未授权设备 ❌

阈值可在GUI的"系统配置"中调整。

---

## 📊 数据库格式

`usb_fingerprint_db.json` 存储设备指纹：

```json
{
  "SanDisk_32G": {
    "fingerprint": {
      "enumeration": {
        "mean": 0.1235,
        "std": 0.0843,
        "count": 3
      },
      "transfers": {
        "1": {
          "mean": 0.000673,
          "std": 0.001183,
          "count": 2320
        },
        "130": {
          "mean": 0.000890,
          "std": 0.001474,
          "count": 1860
        }
      }
    },
    "reg_time": "2026-01-13 15:30:45",
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

**错误**: `找不到 Tshark`

**解决方案**:
- 安装 [Wireshark](https://www.wireshark.org/download.html)
- 在GUI的"系统配置"中设置正确路径
- 或修改 `config.json` 中的 `tshark_path`

#### Q2: GUI程序无法启动

**错误**: `ModuleNotFoundError: No module named 'ttkbootstrap'`

**解决方案**:
```bash
pip install ttkbootstrap
```

#### Q3: 实时采集时GUI无响应

**原因**: 已在最新版本中修复

**确认版本**: 确保使用最新的 `Main_GUI.py` 和 `AutoCatch.py`

#### Q4: 认证相似度太低

**现象**: 相同U盘认证相似度<70%

**解决方案**:
- 增加注册样本数量（5-10个）
- 在相同USB端口采集
- 在GUI中降低阈值（如60%）
- 避免系统高负载时采集

#### Q5: 未提取到特征

**现象**: 指纹数据为空

**可能原因**:
- USB接口设置错误
- 采集数据不足
- pcapng文件无USB数据

**解决方案**:
- 在命令行运行 `tshark -D` 查看可用接口
- 在GUI配置中正确设置接口（如：USBPcap3）
- 增加采集时间或数据量

---

## � 高级配置

### 配置文件 (config.json)

GUI自动管理配置，也可手动编辑：

```json
{
  "tshark_path": "C:\\Program Files\\Wireshark\\tshark.exe",
  "interface": "USBPcap3",
  "base_folder": "devices",
  "db_file": "usb_fingerprint_db.json",
  "auth_threshold": 70.0,
  "theme": "darkly",
  "window_geometry": "1100x750"
}
```

### 调整采集参数

编辑 `AutoCatch.py`：

```python
target_size_mb=50  # 采集的数据量（MB）
```

### 更换GUI主题

在 `config.json` 中修改：

```json
"theme": "darkly"  // 可选: darkly, cyborg, cosmo, flatly等
```

---

## 🎯 应用场景

### 企业安全
- **未授权设备检测**: 识别员工私自使用的U盘
- **设备白名单**: 只允许已注册的U盘
- **数据泄露防护**: 阻止未知U盘接入

### 取证分析
- **设备溯源**: 确认特定U盘是否连接过系统
- **时间线分析**: 结合时间戳建立事件序列

### 研究用途
- **USB设备特性研究**: 分析不同厂商/型号的时序差异
- **物理层指纹**: 探索硬件级别的设备识别

---

## 📝 开发指南

### 模块架构

```
Main_GUI.py          - GUI界面和事件处理
  ├── gui_utils.py        - GUI辅助工具（日志重定向、线程管理）
  ├── AutoCatch.py        - USB流量采集（TShark）
  ├── Register.py         - 指纹注册逻辑
  ├── Authenticate.py     - 指纹认证逻辑
  └── FeatureExtractor.py - 特征提取引擎
       └── pyshark         - pcapng解析
```

### 技术特性

**GUI实现**:
- 框架: tkinter + ttkbootstrap
- 多线程: 避免界面冻结
- 日志重定向: 捕获所有print输出
- 配置持久化: JSON格式存储

**采集交互**:
- 回调机制: 支持GUI/CLI双模式
- 对话框确认: 替代阻塞式input()
- 线程同步: threading.Event

### 扩展开发

#### 添加新特征

在 `FeatureExtractor.py` 中扩展：

```python
def extract_new_feature(cap):
    # 自定义特征提取逻辑
    pass
```

#### 自定义相似度算法

在 `Authenticate.py` 中修改：

```python
def calculate_similarity(feature1, feature2):
    # 使用其他算法：马氏距离、余弦相似度等
    pass
```

---

## � 文档参考

- **AGENTS.md**: 开发者指南和代码规范
- **改进总结_USB指纹识别系统优化.md**: 详细技术文档
- 源码注释: 每个函数都有详细docstring

---

## ✅ 功能清单

- [x] GUI界面
- [x] 设备注册（文件/采集）
- [x] 设备认证（文件/实时）
- [x] 数据库管理
- [x] 配置管理
- [x] 实时日志显示
- [x] 多线程处理
- [x] 自动清理enroll文件夹
- [ ] 实时监控模式
- [ ] 机器学习分类器
- [ ] 批量操作

---

## 🎓 使用建议

### 最佳实践

1. **注册设备**:
   - 采集3-5个样本以提高准确性
   - 在相同USB端口进行采集
   - 避免系统高负载时采集

2. **认证设备**:
   - 首次使用可适当降低阈值（如65%）
   - 观察日志中的相似度详情
   - 多次测试确定最佳阈值

3. **数据管理**:
   - 定期备份 `usb_fingerprint_db.json`
   - 清理不再使用的设备记录
   - 注意 `devices/auth/` 文件会被覆盖

### 安全提示

⚠️ 本系统基于时序特征，存在一定误差：
- 不应作为唯一的安全验证手段
- 建议结合其他认证方式（如硬件ID）
- 定期更新指纹数据库

---

## 📄 版本信息

**当前版本**: 3.0 (GUI版本)  
**更新日期**: 2026-01-13  
**主要更新**:
- ✨ 全新GUI界面
- 🔧 修复实时认证死机问题
- 🔧 修复GUI交互阻塞问题
- ✨ 自动清空enroll文件夹
- 📝 完善配置管理

**作者**: USB Fingerprint Team  
**用途**: 学习研究

---

## 🙏 致谢

感谢以下开源项目：
- [Wireshark](https://www.wireshark.org/) - 网络协议分析
- [pyshark](https://github.com/KimiNewt/pyshark) - Python包解析
- [ttkbootstrap](https://github.com/israel-dryer/ttkbootstrap) - tkinter美化

---

**快速开始**: `python Main_GUI.py` 🚀
