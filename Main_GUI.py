"""
创建前端界面
USB 设备指纹识别系统 - GUI版本
基于tkinter + ttkbootstrap的图形界面
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import ttkbootstrap as ttk_bs
from ttkbootstrap.constants import *
import json
import os
import sys
import threading
from datetime import datetime

# 导入后端模块
import Register
import Authenticate
import AutoCatch
import gui_utils


class USBFingerprintGUI:
    """USB指纹识别系统主界面"""
    
    def __init__(self):
        # 加载配置
        self.config = self.load_config()
        
        # 创建主窗口
        self.root = ttk_bs.Window(
            title="USB 设备指纹识别系统",
            themename=self.config.get('theme', 'darkly'),
            size=(1100, 750)
        )
        self.root.position_center()
        
        # 初始化变量
        self.is_processing = False
        
        # 构建界面
        self.setup_ui()
        
        # 重定向stdout到日志窗口
        sys.stdout = gui_utils.TextRedirector(self.log_text, "stdout")
        sys.stderr = gui_utils.TextRedirector(self.log_text, "stderr")
        
        # 初始化状态栏
        self.update_status_bar()
    
    def load_config(self):
        """加载配置文件"""
        config_file = "config.json"
        default_config = {
            "tshark_path": r"C:\Program Files\Wireshark\tshark.exe",
            "interface": "USBPcap3",
            "base_folder": "devices",
            "db_file": "usb_fingerprint_db.json",
            "auth_threshold": 70.0,
            "theme": "darkly",
            "window_geometry": "1100x750"
        }
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # 合并默认配置（防止缺少新字段）
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            else:
                # 创建默认配置文件
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=2, ensure_ascii=False)
                return default_config
        except Exception as e:
            print(f"[警告] 配置文件加载失败: {e}，使用默认配置")
            return default_config
    
    def save_config(self):
        """保存配置到文件"""
        try:
            with open("config.json", 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            messagebox.showerror("错误", f"配置保存失败: {e}")
            return False
    
    def setup_ui(self):
        """构建整体UI"""
        # 创建顶部标题栏
        self.create_header()
        
        # 创建主选项卡区域
        self.create_tabs()
        
        # 创建底部日志面板
        self.create_log_panel()
        
        # 创建状态栏
        self.create_status_bar()
    
    def create_header(self):
        """创建顶部标题区域"""
        header_frame = ttk_bs.Frame(self.root, bootstyle="dark")
        header_frame.pack(fill=X, padx=10, pady=(10, 5))
        
        title_label = ttk_bs.Label(
            header_frame,
            text="🔐 USB 设备指纹识别系统",
            font=("Microsoft YaHei UI", 18, "bold"),
            bootstyle="inverse-dark"
        )
        title_label.pack(side=LEFT, padx=10)
        
        subtitle_label = ttk_bs.Label(
            header_frame,
            text="基于时序特征的USB设备认证",
            font=("Microsoft YaHei UI", 10),
            bootstyle="inverse-secondary"
        )
        subtitle_label.pack(side=LEFT, padx=5)
    
    def create_tabs(self):
        """创建选项卡"""
        self.notebook = ttk_bs.Notebook(self.root, bootstyle="dark")
        self.notebook.pack(fill=BOTH, expand=YES, padx=10, pady=5)
        
        # 选项卡1: 设备注册
        self.tab_register = ttk_bs.Frame(self.notebook)
        self.notebook.add(self.tab_register, text="📝 设备注册")
        self.create_register_tab()
        
        # 选项卡2: 设备认证
        self.tab_auth = ttk_bs.Frame(self.notebook)
        self.notebook.add(self.tab_auth, text="🔍 设备认证")
        self.create_auth_tab()
        
        # 选项卡3: 数据库管理
        self.tab_database = ttk_bs.Frame(self.notebook)
        self.notebook.add(self.tab_database, text="💾 数据库管理")
        self.create_database_tab()
        
        # 选项卡4: 系统配置
        self.tab_config = ttk_bs.Frame(self.notebook)
        self.notebook.add(self.tab_config, text="⚙ 系统配置")
        self.create_config_tab()
    
    def create_register_tab(self):
        """创建设备注册标签页"""
        # 注册方式选择
        mode_frame = ttk_bs.Labelframe(
            self.tab_register,
            text="注册方式",
            bootstyle="primary",
            padding=15
        )
        mode_frame.pack(fill=X, padx=20, pady=10)
        
        self.register_mode = tk.StringVar(value="file")
        
        ttk_bs.Radiobutton(
            mode_frame,
            text="📁 从文件注册 (已有 .pcapng 文件)",
            variable=self.register_mode,
            value="file",
            bootstyle="primary-toolbutton",
            command=self.toggle_register_mode
        ).pack(anchor=W, pady=5)
        
        ttk_bs.Radiobutton(
            mode_frame,
            text="🔄 采集+注册 (新设备录入)",
            variable=self.register_mode,
            value="capture",
            bootstyle="primary-toolbutton",
            command=self.toggle_register_mode
        ).pack(anchor=W, pady=5)
        
        # 文件注册配置区
        self.file_reg_frame = ttk_bs.Labelframe(
            self.tab_register,
            text="文件注册配置",
            bootstyle="info",
            padding=15
        )
        self.file_reg_frame.pack(fill=X, padx=20, pady=10)
        
        # 文件夹路径
        path_row = ttk_bs.Frame(self.file_reg_frame)
        path_row.pack(fill=X, pady=5)
        ttk_bs.Label(path_row, text="数据文件夹:", width=12).pack(side=LEFT)
        self.reg_folder_var = tk.StringVar(
            value=os.path.join(self.config['base_folder'], 'enroll')
        )
        ttk_bs.Entry(
            path_row,
            textvariable=self.reg_folder_var,
            bootstyle="info"
        ).pack(side=LEFT, fill=X, expand=YES, padx=5)
        ttk_bs.Button(
            path_row,
            text="浏览",
            bootstyle="info-outline",
            command=self.browse_register_folder
        ).pack(side=LEFT)
        
        # 设备名称
        name_row = ttk_bs.Frame(self.file_reg_frame)
        name_row.pack(fill=X, pady=5)
        ttk_bs.Label(name_row, text="设备名称:", width=12).pack(side=LEFT)
        self.reg_device_name_var = tk.StringVar()
        ttk_bs.Entry(
            name_row,
            textvariable=self.reg_device_name_var,
            bootstyle="info"
        ).pack(side=LEFT, fill=X, expand=YES, padx=5)
        
        # 执行按钮
        ttk_bs.Button(
            self.file_reg_frame,
            text="✓ 开始注册",
            bootstyle="success",
            command=self.run_file_registration
        ).pack(pady=10)
        
        # 采集+注册配置区
        self.capture_reg_frame = ttk_bs.Labelframe(
            self.tab_register,
            text="采集+注册配置",
            bootstyle="warning",
            padding=15
        )
        self.capture_reg_frame.pack(fill=X, padx=20, pady=10)
        self.capture_reg_frame.pack_forget()  # 默认隐藏
        
        # U盘盘符
        drive_row = ttk_bs.Frame(self.capture_reg_frame)
        drive_row.pack(fill=X, pady=5)
        ttk_bs.Label(drive_row, text="U盘盘符:", width=12).pack(side=LEFT)
        self.capture_drive_var = tk.StringVar()
        ttk_bs.Entry(
            drive_row,
            textvariable=self.capture_drive_var,
            bootstyle="warning",
            width=5
        ).pack(side=LEFT, padx=5)
        ttk_bs.Label(drive_row, text="(例如: E)", bootstyle="secondary").pack(side=LEFT)
        
        # 设备名称
        name2_row = ttk_bs.Frame(self.capture_reg_frame)
        name2_row.pack(fill=X, pady=5)
        ttk_bs.Label(name2_row, text="设备名称:", width=12).pack(side=LEFT)
        self.capture_device_name_var = tk.StringVar()
        ttk_bs.Entry(
            name2_row,
            textvariable=self.capture_device_name_var,
            bootstyle="warning"
        ).pack(side=LEFT, fill=X, expand=YES, padx=5)
        
        # 采集次数
        count_row = ttk_bs.Frame(self.capture_reg_frame)
        count_row.pack(fill=X, pady=5)
        ttk_bs.Label(count_row, text="采集次数:", width=12).pack(side=LEFT)
        self.capture_count_var = tk.IntVar(value=3)
        ttk_bs.Spinbox(
            count_row,
            from_=1,
            to=10,
            textvariable=self.capture_count_var,
            bootstyle="warning",
            width=10
        ).pack(side=LEFT, padx=5)
        ttk_bs.Label(count_row, text="(建议 3-5 次)", bootstyle="secondary").pack(side=LEFT)
        
        # 执行按钮
        ttk_bs.Button(
            self.capture_reg_frame,
            text="🎬 开始采集",
            bootstyle="warning",
            command=self.run_capture_and_register
        ).pack(pady=10)
    
    def create_auth_tab(self):
        """创建设备认证标签页"""
        # 认证方式选择
        mode_frame = ttk_bs.Labelframe(
            self.tab_auth,
            text="认证方式",
            bootstyle="primary",
            padding=15
        )
        mode_frame.pack(fill=X, padx=20, pady=10)
        
        self.auth_mode = tk.StringVar(value="file")
        
        ttk_bs.Radiobutton(
            mode_frame,
            text="📁 从文件认证 (使用已有 .pcapng)",
            variable=self.auth_mode,
            value="file",
            bootstyle="primary-toolbutton",
            command=self.toggle_auth_mode
        ).pack(anchor=W, pady=5)
        
        ttk_bs.Radiobutton(
            mode_frame,
            text="🔴 实时采集认证 (插拔U盘)",
            variable=self.auth_mode,
            value="live",
            bootstyle="primary-toolbutton",
            command=self.toggle_auth_mode
        ).pack(anchor=W, pady=5)
        
        # 文件认证配置
        self.file_auth_frame = ttk_bs.Labelframe(
            self.tab_auth,
            text="文件认证配置",
            bootstyle="info",
            padding=15
        )
        self.file_auth_frame.pack(fill=X, padx=20, pady=10)
        
        # 文件夹路径
        path_row = ttk_bs.Frame(self.file_auth_frame)
        path_row.pack(fill=X, pady=5)
        ttk_bs.Label(path_row, text="数据文件夹:", width=12).pack(side=LEFT)
        self.auth_folder_var = tk.StringVar(
            value=os.path.join(self.config['base_folder'], 'auth')
        )
        ttk_bs.Entry(
            path_row,
            textvariable=self.auth_folder_var,
            bootstyle="info"
        ).pack(side=LEFT, fill=X, expand=YES, padx=5)
        ttk_bs.Button(
            path_row,
            text="浏览",
            bootstyle="info-outline",
            command=self.browse_auth_folder
        ).pack(side=LEFT)
        
        # 实时采集配置
        self.live_auth_frame = ttk_bs.Labelframe(
            self.tab_auth,
            text="实时采集配置",
            bootstyle="warning",
            padding=15
        )
        self.live_auth_frame.pack(fill=X, padx=20, pady=10)
        self.live_auth_frame.pack_forget()  # 默认隐藏
        
        drive_row = ttk_bs.Frame(self.live_auth_frame)
        drive_row.pack(fill=X, pady=5)
        ttk_bs.Label(drive_row, text="U盘盘符:", width=12).pack(side=LEFT)
        self.auth_drive_var = tk.StringVar()
        ttk_bs.Entry(
            drive_row,
            textvariable=self.auth_drive_var,
            bootstyle="warning",
            width=5
        ).pack(side=LEFT, padx=5)
        ttk_bs.Label(drive_row, text="(例如: E)", bootstyle="secondary").pack(side=LEFT)
        
        # 通用配置
        common_frame = ttk_bs.Labelframe(
            self.tab_auth,
            text="认证参数",
            bootstyle="success",
            padding=15
        )
        common_frame.pack(fill=X, padx=20, pady=10)
        
        # 目标设备ID
        device_row = ttk_bs.Frame(common_frame)
        device_row.pack(fill=X, pady=5)
        ttk_bs.Label(device_row, text="目标设备ID:", width=12).pack(side=LEFT)
        self.auth_device_id_var = tk.StringVar()
        ttk_bs.Entry(
            device_row,
            textvariable=self.auth_device_id_var,
            bootstyle="success"
        ).pack(side=LEFT, fill=X, expand=YES, padx=5)
        ttk_bs.Label(
            device_row,
            text="(留空则与所有设备对比)",
            bootstyle="secondary"
        ).pack(side=LEFT)
        
        # 阈值
        threshold_row = ttk_bs.Frame(common_frame)
        threshold_row.pack(fill=X, pady=5)
        ttk_bs.Label(threshold_row, text="相似度阈值:", width=12).pack(side=LEFT)
        self.auth_threshold_var = tk.DoubleVar(value=self.config['auth_threshold'])
        ttk_bs.Scale(
            threshold_row,
            from_=0,
            to=100,
            variable=self.auth_threshold_var,
            bootstyle="success"
        ).pack(side=LEFT, fill=X, expand=YES, padx=5)
        self.threshold_label = ttk_bs.Label(
            threshold_row,
            text=f"{self.auth_threshold_var.get():.1f}",
            width=8,
            bootstyle="inverse-success"
        )
        self.threshold_label.pack(side=LEFT)
        self.auth_threshold_var.trace_add('write', self.update_threshold_label)
        
        # 执行按钮
        ttk_bs.Button(
            common_frame,
            text="🔍 开始认证",
            bootstyle="success",
            command=self.run_authentication
        ).pack(pady=10)
        
        # 认证结果显示区
        result_frame = ttk_bs.Labelframe(
            self.tab_auth,
            text="认证结果",
            bootstyle="secondary",
            padding=15
        )
        result_frame.pack(fill=BOTH, expand=YES, padx=20, pady=10)
        
        self.auth_result_label = ttk_bs.Label(
            result_frame,
            text="等待认证...",
            font=("Microsoft YaHei UI", 12),
            bootstyle="secondary",
            anchor=CENTER
        )
        self.auth_result_label.pack(fill=BOTH, expand=YES)
    
    def create_database_tab(self):
        """创建数据库管理标签页"""
        # 顶部按钮栏
        btn_frame = ttk_bs.Frame(self.tab_database)
        btn_frame.pack(fill=X, padx=20, pady=10)
        
        ttk_bs.Button(
            btn_frame,
            text="🔄 刷新列表",
            bootstyle="info",
            command=self.load_database_list
        ).pack(side=LEFT, padx=5)
        
        ttk_bs.Button(
            btn_frame,
            text="🗑️ 删除选中",
            bootstyle="danger",
            command=self.delete_selected_device
        ).pack(side=LEFT, padx=5)
        
        # 设备列表表格
        list_frame = ttk_bs.Labelframe(
            self.tab_database,
            text="已注册设备列表",
            bootstyle="info",
            padding=10
        )
        list_frame.pack(fill=BOTH, expand=YES, padx=20, pady=10)
        
        # 创建Treeview
        columns = ("device_id", "reg_time", "samples", "files")
        self.db_tree = ttk_bs.Treeview(
            list_frame,
            columns=columns,
            show='headings',
            bootstyle="info",
            selectmode='browse'
        )
        
        # 设置列标题
        self.db_tree.heading("device_id", text="设备ID")
        self.db_tree.heading("reg_time", text="注册时间")
        self.db_tree.heading("samples", text="样本数量")
        self.db_tree.heading("files", text="源文件数")
        
        # 设置列宽
        self.db_tree.column("device_id", width=200)
        self.db_tree.column("reg_time", width=180)
        self.db_tree.column("samples", width=100, anchor=CENTER)
        self.db_tree.column("files", width=100, anchor=CENTER)
        
        # 添加滚动条
        scrollbar = ttk_bs.Scrollbar(
            list_frame,
            orient=VERTICAL,
            command=self.db_tree.yview
        )
        self.db_tree.configure(yscrollcommand=scrollbar.set)
        
        self.db_tree.pack(side=LEFT, fill=BOTH, expand=YES)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        # 初始加载数据
        self.load_database_list()
    
    def create_config_tab(self):
        """创建系统配置标签页"""
        config_frame = ttk_bs.Frame(self.tab_config, padding=20)
        config_frame.pack(fill=BOTH, expand=YES)
        
        # TShark路径
        tshark_frame = ttk_bs.Labelframe(
            config_frame,
            text="TShark 配置",
            bootstyle="primary",
            padding=15
        )
        tshark_frame.pack(fill=X, pady=10)
        
        path_row = ttk_bs.Frame(tshark_frame)
        path_row.pack(fill=X, pady=5)
        ttk_bs.Label(path_row, text="TShark路径:", width=12).pack(side=LEFT)
        self.tshark_path_var = tk.StringVar(value=self.config['tshark_path'])
        ttk_bs.Entry(
            path_row,
            textvariable=self.tshark_path_var,
            bootstyle="primary"
        ).pack(side=LEFT, fill=X, expand=YES, padx=5)
        ttk_bs.Button(
            path_row,
            text="浏览",
            bootstyle="primary-outline",
            command=self.browse_tshark
        ).pack(side=LEFT)
        
        # USB接口
        interface_row = ttk_bs.Frame(tshark_frame)
        interface_row.pack(fill=X, pady=5)
        ttk_bs.Label(interface_row, text="USB接口:", width=12).pack(side=LEFT)
        self.interface_var = tk.StringVar(value=self.config['interface'])
        ttk_bs.Entry(
            interface_row,
            textvariable=self.interface_var,
            bootstyle="primary"
        ).pack(side=LEFT, fill=X, expand=YES, padx=5)
        
        # 数据存储配置
        storage_frame = ttk_bs.Labelframe(
            config_frame,
            text="数据存储配置",
            bootstyle="info",
            padding=15
        )
        storage_frame.pack(fill=X, pady=10)
        
        base_row = ttk_bs.Frame(storage_frame)
        base_row.pack(fill=X, pady=5)
        ttk_bs.Label(base_row, text="数据根目录:", width=12).pack(side=LEFT)
        self.base_folder_var = tk.StringVar(value=self.config['base_folder'])
        ttk_bs.Entry(
            base_row,
            textvariable=self.base_folder_var,
            bootstyle="info"
        ).pack(side=LEFT, fill=X, expand=YES, padx=5)
        
        db_row = ttk_bs.Frame(storage_frame)
        db_row.pack(fill=X, pady=5)
        ttk_bs.Label(db_row, text="数据库文件:", width=12).pack(side=LEFT)
        self.db_file_var = tk.StringVar(value=self.config['db_file'])
        ttk_bs.Entry(
            db_row,
            textvariable=self.db_file_var,
            bootstyle="info"
        ).pack(side=LEFT, fill=X, expand=YES, padx=5)
        
        # 保存按钮
        btn_frame = ttk_bs.Frame(config_frame)
        btn_frame.pack(pady=20)
        
        ttk_bs.Button(
            btn_frame,
            text="💾 保存配置",
            bootstyle="success",
            command=self.save_configuration,
            width=20
        ).pack(side=LEFT, padx=5)
        
        ttk_bs.Button(
            btn_frame,
            text="🔄 重置默认",
            bootstyle="warning-outline",
            command=self.reset_configuration,
            width=20
        ).pack(side=LEFT, padx=5)
    
    def create_log_panel(self):
        """创建日志显示面板"""
        log_frame = ttk_bs.Labelframe(
            self.root,
            text="📋 系统日志",
            bootstyle="secondary",
            padding=10
        )
        log_frame.pack(fill=BOTH, expand=YES, padx=10, pady=5)
        
        # 创建更大的日志窗口（高度从10改为18）
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=18,  # 增大日志窗口高度
            state='disabled',
            wrap='word',
            bg='#1e1e1e',
            fg='#d4d4d4',
            insertbackground='white',
            font=('Consolas', 9)
        )
        
        # 配置标签颜色
        self.log_text.tag_config('stdout', foreground='#d4d4d4')
        self.log_text.tag_config('stderr', foreground='#f48771')
        self.log_text.tag_config('success', foreground='#4ec9b0')
        self.log_text.tag_config('warning', foreground='#dcdcaa')
        self.log_text.tag_config('error', foreground='#f48771')
        
        self.log_text.pack(fill=BOTH, expand=YES)
        
        # 清空日志按钮
        btn_row = ttk_bs.Frame(log_frame)
        btn_row.pack(fill=X, pady=(5, 0))
        
        ttk_bs.Button(
            btn_row,
            text="清空日志",
            bootstyle="secondary-outline",
            command=lambda: gui_utils.clear_log_widget(self.log_text)
        ).pack(side=RIGHT)
    
    def create_status_bar(self):
        """创建状态栏"""
        self.status_bar = ttk_bs.Frame(self.root, bootstyle="secondary")
        self.status_bar.pack(fill=X, side=BOTTOM)
        
        self.status_label = ttk_bs.Label(
            self.status_bar,
            text="就绪",
            bootstyle="inverse-secondary",
            padding=5
        )
        self.status_label.pack(side=LEFT)
        
        self.db_count_label = ttk_bs.Label(
            self.status_bar,
            text="已注册设备: 0",
            bootstyle="inverse-secondary",
            padding=5
        )
        self.db_count_label.pack(side=RIGHT)
    
    # ==================== 事件处理方法 ====================
    
    def gui_confirm_callback(self, title, message):
        """
        GUI模式下的确认回调函数
        在主线程中显示确认对话框，使用Event同步
        """
        import threading
        
        result = [False]
        event = threading.Event()
        
        def show_dialog():
            result[0] = messagebox.askokcancel(title, message)
            event.set()  # 标记对话框已关闭
        
        # 在主线程中执行对话框
        self.root.after(0, show_dialog)
        
        # 等待用户响应（最多5分钟）
        event.wait(timeout=300)
        
        return result[0]
    
    def toggle_register_mode(self):
        """切换注册模式显示"""
        if self.register_mode.get() == "file":
            self.file_reg_frame.pack(fill=X, padx=20, pady=10)
            self.capture_reg_frame.pack_forget()
        else:
            self.file_reg_frame.pack_forget()
            self.capture_reg_frame.pack(fill=X, padx=20, pady=10)
    
    def toggle_auth_mode(self):
        """切换认证模式显示"""
        if self.auth_mode.get() == "file":
            self.file_auth_frame.pack(fill=X, padx=20, pady=10)
            self.live_auth_frame.pack_forget()
        else:
            self.file_auth_frame.pack_forget()
            self.live_auth_frame.pack(fill=X, padx=20, pady=10)
    
    def update_threshold_label(self, *args):
        """更新阈值显示标签"""
        self.threshold_label.config(text=f"{self.auth_threshold_var.get():.1f}")
    
    def browse_register_folder(self):
        """浏览选择注册文件夹"""
        folder = filedialog.askdirectory(title="选择注册数据文件夹")
        if folder:
            self.reg_folder_var.set(folder)
    
    def browse_auth_folder(self):
        """浏览选择认证文件夹"""
        folder = filedialog.askdirectory(title="选择认证数据文件夹")
        if folder:
            self.auth_folder_var.set(folder)
    
    def browse_tshark(self):
        """浏览选择TShark可执行文件"""
        file = filedialog.askopenfilename(
            title="选择TShark可执行文件",
            filetypes=[("可执行文件", "*.exe"), ("所有文件", "*.*")]
        )
        if file:
            self.tshark_path_var.set(file)
    
    # ==================== 业务逻辑方法 ====================
    
    def run_file_registration(self):
        """执行文件注册"""
        if self.is_processing:
            messagebox.showwarning("警告", "系统正在处理中，请稍候...")
            return
        
        folder = self.reg_folder_var.get().strip()
        device_name = self.reg_device_name_var.get().strip()
        
        # 验证输入
        if not device_name:
            messagebox.showerror("错误", "请输入设备名称")
            return
        
        valid, msg = gui_utils.validate_path(folder, must_exist=True, is_dir=True)
        if not valid:
            messagebox.showerror("错误", msg)
            return
        
        # 检查文件夹中是否有pcapng文件
        files = [f for f in os.listdir(folder) if f.endswith('.pcapng')]
        if not files:
            messagebox.showerror("错误", f"文件夹中没有 .pcapng 文件\n{folder}")
            return
        
        # 在后台线程执行
        self.is_processing = True
        self.status_label.config(text="正在注册设备...")
        
        def task():
            success = Register.run_registration(
                device_id=device_name,
                enroll_folder=folder,
                db_file=self.config['db_file']
            )
            return success
        
        def on_complete(success):
            self.is_processing = False
            if success:
                messagebox.showinfo("成功", f"设备 '{device_name}' 注册成功！")
                self.load_database_list()
                self.update_status_bar()
            else:
                messagebox.showerror("失败", "设备注册失败，请查看日志")
            self.status_label.config(text="就绪")
        
        def on_error(e):
            self.is_processing = False
            messagebox.showerror("错误", f"注册过程出错: {e}")
            self.status_label.config(text="就绪")
        
        gui_utils.run_in_thread(task, on_complete, on_error)
    
    def run_capture_and_register(self):
        """执行采集+注册"""
        if self.is_processing:
            messagebox.showwarning("警告", "系统正在处理中，请稍候...")
            return
        
        drive = self.capture_drive_var.get().strip().upper()
        device_name = self.capture_device_name_var.get().strip()
        count = self.capture_count_var.get()
        
        if not drive:
            messagebox.showerror("错误", "请输入U盘盘符")
            return
        
        if not device_name:
            messagebox.showerror("错误", "请输入设备名称")
            return
        
        # 确认开始
        if not messagebox.askyesno("确认", f"即将开始采集 {count} 次\n请确保U盘盘符为 {drive}:\n准备好了吗？"):
            return
        
        self.is_processing = True
        self.status_label.config(text=f"采集中 (0/{count})...")
        
        def task():
            enroll_path = os.path.join(self.config['base_folder'], 'enroll')
            
            # 循环采集
            for i in range(1, count + 1):
                print(f"\n=== 采集进度: {i}/{count} ===")
                # 更新状态栏 - 正确捕获循环变量
                self.root.after(
                    0,
                    lambda current=i, total=count: self.status_label.config(text=f"采集中 ({current}/{total})...")
                )
                
                success = AutoCatch.run_single_capture(
                    tshark_path=self.config['tshark_path'],
                    interface=self.config['interface'],
                    output_base_folder=self.config['base_folder'],
                    sub_folder="enroll",
                    file_name=f"capture_{i}.pcapng",
                    target_size_mb=50,
                    drive_letter=drive,
                    confirm_callback=self.gui_confirm_callback  # GUI模式回调
                )
                
                if not success:
                    print(f"[警告] 第 {i} 次采集失败")
            
            # 采集完成，开始注册
            print("\n=== 开始生成指纹 ===")
            self.root.after(0, lambda: self.status_label.config(text="生成指纹中..."))
            
            success = Register.run_registration(
                device_id=device_name,
                enroll_folder=enroll_path,
                db_file=self.config['db_file']
            )
            return success
        
        def on_complete(success):
            self.is_processing = False
            if success:
                messagebox.showinfo("成功", f"设备 '{device_name}' 录入成功！")
                self.load_database_list()
                self.update_status_bar()
            else:
                messagebox.showwarning("警告", "采集完成，但注册失败，请查看日志")
            self.status_label.config(text="就绪")
        
        def on_error(e):
            self.is_processing = False
            messagebox.showerror("错误", f"采集过程出错: {e}")
            self.status_label.config(text="就绪")
        
        gui_utils.run_in_thread(task, on_complete, on_error)
    
    def run_authentication(self):
        """执行设备认证"""
        if self.is_processing:
            messagebox.showwarning("警告", "系统正在处理中，请稍候...")
            return
        
        auth_mode = self.auth_mode.get()
        device_id = self.auth_device_id_var.get().strip() or None
        threshold = self.auth_threshold_var.get()
        
        # 检查数据库
        if not os.path.exists(self.config['db_file']):
            messagebox.showerror("错误", "指纹数据库不存在，请先注册设备")
            return
        
        auth_folder = os.path.join(self.config['base_folder'], 'auth')
        
        # 如果是实时采集模式
        if auth_mode == "live":
            drive = self.auth_drive_var.get().strip().upper()
            if not drive:
                messagebox.showerror("错误", "请输入U盘盘符")
                return
            
            if not messagebox.askyesno("确认", f"即将采集U盘 {drive}: 的流量\n准备好了吗？"):
                return
            
            # 标记正在处理，但采集操作在后台线程中进行
            self.is_processing = True
            self.status_label.config(text="准备采集验证数据...")
        else:
            # 文件模式
            auth_folder = self.auth_folder_var.get().strip()
            valid, msg = gui_utils.validate_path(auth_folder, must_exist=True, is_dir=True)
            if not valid:
                messagebox.showerror("错误", msg)
                return
            
            files = [f for f in os.listdir(auth_folder) if f.endswith('.pcapng')]
            if not files:
                messagebox.showerror("错误", f"文件夹中没有 .pcapng 文件\n{auth_folder}")
                return
        
        # 执行认证（包括实时采集，如果需要）
        self.is_processing = True
        self.status_label.config(text="正在认证...")
        self.auth_result_label.config(text="认证中...", bootstyle="warning")
        
        def task():
            # 如果是实时模式，先在后台线程中采集
            if auth_mode == "live":
                print("\n=== 开始采集验证数据 ===")
                self.root.after(0, lambda: self.status_label.config(text="正在采集验证数据..."))
                
                success = AutoCatch.run_single_capture(
                    tshark_path=self.config['tshark_path'],
                    interface=self.config['interface'],
                    output_base_folder=self.config['base_folder'],
                    sub_folder="auth",
                    file_name="auth_verify.pcapng",
                    target_size_mb=50,
                    drive_letter=drive,
                    confirm_callback=self.gui_confirm_callback  # GUI模式回调
                )
                
                if not success:
                    return None, None, None  # 采集失败
                
                # 采集成功，使用默认auth文件夹
                actual_auth_folder = os.path.join(self.config['base_folder'], 'auth')
            else:
                actual_auth_folder = auth_folder
            
            # 执行认证
            print("\n=== 开始设备认证 ===")
            self.root.after(0, lambda: self.status_label.config(text="正在认证..."))
            
            passed, match_id, score = Authenticate.authenticate_device(
                auth_folder=actual_auth_folder,
                db_file=self.config['db_file'],
                device_id=device_id,
                threshold=threshold
            )
            return passed, match_id, score
        
        def on_complete(result):
            self.is_processing = False
            
            # 检查采集失败的情况
            if result is None or result [0] is None:
                messagebox.showerror("错误", "采集失败，无法继续认证")
                self.auth_result_label.config(text="采集失败", bootstyle="danger")
                self.status_label.config(text="就绪")
                return
            
            passed, match_id, score = result
            
            if passed:
                result_text = f"✓ 认证通过\n\n匹配设备: {match_id}\n相似度: {score:.2f}%\n\n建议操作: 允许访问"
                self.auth_result_label.config(
                    text=result_text,
                    bootstyle="success"
                )
                messagebox.showinfo("认证通过", f"设备 '{match_id}' 认证成功！\n相似度: {score:.2f}%")
            else:
                if match_id:
                    result_text = f"✗ 认证失败\n\n最佳匹配: {match_id}\n相似度: {score:.2f}%\n阈值: {threshold:.1f}%\n\n建议操作: 阻止访问"
                else:
                    result_text = f"✗ 认证失败\n\n未找到匹配设备\n\n建议操作: 阻止访问"
                
                self.auth_result_label.config(
                    text=result_text,
                    bootstyle="danger"
                )
                messagebox.showwarning("认证失败", "设备认证失败，可能是未授权设备")
            
            self.status_label.config(text="就绪")
        
        def on_error(e):
            self.is_processing = False
            messagebox.showerror("错误", f"认证过程出错: {e}")
            self.auth_result_label.config(text="认证出错", bootstyle="danger")
            self.status_label.config(text="就绪")
        
        gui_utils.run_in_thread(task, on_complete, on_error)
    
    def load_database_list(self):
        """加载并显示数据库中的设备列表"""
        # 清空现有数据
        for item in self.db_tree.get_children():
            self.db_tree.delete(item)
        
        # 读取数据库
        if not os.path.exists(self.config['db_file']):
            return
        
        try:
            with open(self.config['db_file'], 'r', encoding='utf-8') as f:
                db = json.load(f)
            
            for device_id, info in db.items():
                reg_time = info.get('reg_time', 'N/A')
                samples = info.get('samples_count', 0)
                files = len(info.get('source_files', []))
                
                self.db_tree.insert(
                    '',
                    'end',
                    values=(device_id, reg_time, samples, files)
                )
        except Exception as e:
            print(f"[错误] 加载数据库失败: {e}")
    
    def delete_selected_device(self):
        """删除选中的设备"""
        selection = self.db_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要删除的设备")
            return
        
        item = selection[0]
        device_id = self.db_tree.item(item)['values'][0]
        
        if not messagebox.askyesno("确认删除", f"确定要删除设备 '{device_id}' 吗？"):
            return
        
        try:
            with open(self.config['db_file'], 'r', encoding='utf-8') as f:
                db = json.load(f)
            
            if device_id in db:
                del db[device_id]
                
                with open(self.config['db_file'], 'w', encoding='utf-8') as f:
                    json.dump(db, f, indent=2, ensure_ascii=False)
                
                self.db_tree.delete(item)
                self.update_status_bar()
                messagebox.showinfo("成功", f"设备 '{device_id}' 已删除")
        except Exception as e:
            messagebox.showerror("错误", f"删除失败: {e}")
    
    def save_configuration(self):
        """保存配置"""
        self.config['tshark_path'] = self.tshark_path_var.get()
        self.config['interface'] = self.interface_var.get()
        self.config['base_folder'] = self.base_folder_var.get()
        self.config['db_file'] = self.db_file_var.get()
        
        if self.save_config():
            messagebox.showinfo("成功", "配置已保存！")
    
    def reset_configuration(self):
        """重置为默认配置"""
        if not messagebox.askyesno("确认", "确定要重置所有配置为默认值吗？"):
            return
        
        # 删除配置文件并重新加载
        if os.path.exists("config.json"):
            os.remove("config.json")
        
        self.config = self.load_config()
        
        # 更新UI
        self.tshark_path_var.set(self.config['tshark_path'])
        self.interface_var.set(self.config['interface'])
        self.base_folder_var.set(self.config['base_folder'])
        self.db_file_var.set(self.config['db_file'])
        self.auth_threshold_var.set(self.config['auth_threshold'])
        
        messagebox.showinfo("成功", "配置已重置为默认值")
    
    def update_status_bar(self):
        """更新状态栏信息"""
        try:
            if os.path.exists(self.config['db_file']):
                with open(self.config['db_file'], 'r', encoding='utf-8') as f:
                    db = json.load(f)
                    count = len(db)
                    self.db_count_label.config(text=f"已注册设备: {count}")
            else:
                self.db_count_label.config(text="已注册设备: 0")
        except:
            self.db_count_label.config(text="已注册设备: ?")
    
    def run(self):
        """启动GUI"""
        print("=== USB 设备指纹识别系统已启动 ===")
        print(f"配置文件: {os.path.abspath('config.json')}")
        print(f"数据库: {os.path.abspath(self.config['db_file'])}")
        print("=" * 50)
        self.root.mainloop()


if __name__ == "__main__":
    try:
        app = USBFingerprintGUI()
        app.run()
    except Exception as e:
        print(f"程序启动失败: {e}")
        import traceback
        traceback.print_exc()
