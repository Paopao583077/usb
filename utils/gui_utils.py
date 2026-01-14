"""
GUI辅助工具模块
提供日志重定向、线程管理、路径验证等功能
"""

import sys
import os
import threading
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext


class TextRedirector:
    """将stdout/stderr重定向到Text组件"""
    
    def __init__(self, text_widget, tag="stdout"):
        self.text_widget = text_widget
        self.tag = tag
        
    def write(self, message):
        if message.strip():  # 忽略空行
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, message, self.tag)
            self.text_widget.see(tk.END)  # 自动滚动到底部
            self.text_widget.configure(state='disabled')
            self.text_widget.update_idletasks()
    
    def flush(self):
        pass


def run_in_thread(func, on_complete=None, on_error=None):
    """
    在后台线程执行函数，避免GUI冻结
    
    Args:
        func: 要执行的函数
        on_complete: 完成后的回调函数（在主线程执行）
        on_error: 出错时的回调函数（在主线程执行）
    """
    def wrapper():
        try:
            result = func()
            if on_complete:
                on_complete(result)
        except Exception as e:
            if on_error:
                on_error(e)
            else:
                print(f"[错误] 线程执行失败: {e}")
    
    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()
    return thread


def validate_path(path, must_exist=True, is_dir=False):
    """
    验证路径有效性
    
    Args:
        path: 路径字符串
        must_exist: 是否必须存在
        is_dir: 是否必须是目录
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not path or not path.strip():
        return False, "路径不能为空"
    
    path = path.strip()
    
    if must_exist:
        if not os.path.exists(path):
            return False, f"路径不存在: {path}"
        
        if is_dir and not os.path.isdir(path):
            return False, f"路径不是目录: {path}"
        
        if not is_dir and not os.path.isfile(path):
            return False, f"路径不是文件: {path}"
    
    return True, ""


def format_timestamp(timestamp_str=None):
    """
    格式化时间戳
    
    Args:
        timestamp_str: ISO格式时间字符串，None则返回当前时间
        
    Returns:
        str: 格式化后的时间字符串
    """
    if timestamp_str:
        try:
            dt = datetime.fromisoformat(timestamp_str)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return timestamp_str
    else:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def create_log_widget(parent):
    """
    创建统一样式的日志显示组件
    
    Args:
        parent: 父容器
        
    Returns:
        ScrolledText: 配置好的日志文本框
    """
    log_widget = scrolledtext.ScrolledText(
        parent,
        height=10,
        state='disabled',
        wrap='word',
        bg='#1e1e1e',
        fg='#d4d4d4',
        insertbackground='white',
        font=('Consolas', 9)
    )
    
    # 配置标签颜色
    log_widget.tag_config('stdout', foreground='#d4d4d4')
    log_widget.tag_config('stderr', foreground='#f48771')
    log_widget.tag_config('success', foreground='#4ec9b0')
    log_widget.tag_config('warning', foreground='#dcdcaa')
    log_widget.tag_config('error', foreground='#f48771')
    
    return log_widget


def clear_log_widget(log_widget):
    """清空日志组件内容"""
    log_widget.configure(state='normal')
    log_widget.delete(1.0, tk.END)
    log_widget.configure(state='disabled')


def log_message(log_widget, message, level='info'):
    """
    向日志组件添加消息
    
    Args:
        log_widget: 日志文本框
        message: 消息内容
        level: 日志级别 (info/success/warning/error)
    """
    tag_map = {
        'info': 'stdout',
        'success': 'success',
        'warning': 'warning',
        'error': 'error'
    }
    
    tag = tag_map.get(level, 'stdout')
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted_msg = f"[{timestamp}] {message}\n"
    
    log_widget.configure(state='normal')
    log_widget.insert(tk.END, formatted_msg, tag)
    log_widget.see(tk.END)
    log_widget.configure(state='disabled')
    log_widget.update_idletasks()
