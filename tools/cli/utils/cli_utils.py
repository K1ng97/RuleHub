#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI工具函数模块
提供CLI通用的辅助函数
"""

import os
import sys
import json
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
import logging
from colorama import Fore, Style, init as colorama_init
from tabulate import tabulate

# 初始化colorama
colorama_init(autoreset=True)

logger = logging.getLogger(__name__)

# 颜色常量定义
class Colors:
    """颜色常量类"""
    SUCCESS = Fore.GREEN
    ERROR = Fore.RED
    WARNING = Fore.YELLOW
    INFO = Fore.BLUE
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Style.DIM

def print_success(message: str) -> None:
    """
    打印成功信息
    
    Args:
        message: 要打印的信息
    """
    print(f"{Colors.SUCCESS}{message}{Colors.RESET}")

def print_error(message: str) -> None:
    """
    打印错误信息
    
    Args:
        message: 要打印的信息
    """
    print(f"{Colors.ERROR}{message}{Colors.RESET}")

def print_warning(message: str) -> None:
    """
    打印警告信息
    
    Args:
        message: 要打印的信息
    """
    print(f"{Colors.WARNING}{message}{Colors.RESET}")

def print_info(message: str) -> None:
    """
    打印信息
    
    Args:
        message: 要打印的信息
    """
    print(f"{Colors.INFO}{message}{Colors.RESET}")

def print_header(title: str) -> None:
    """
    打印标题
    
    Args:
        title: 标题内容
    """
    width = min(os.get_terminal_size().columns, 80)
    print(f"{Colors.BOLD}{title.center(width)}{Colors.RESET}")
    print(f"{Colors.DIM}{'-' * width}{Colors.RESET}")

def print_table(headers: List[str], data: List[List[Any]], title: Optional[str] = None) -> None:
    """
    打印表格
    
    Args:
        headers: 表格头
        data: 表格数据
        title: 表格标题
    """
    if title:
        print_header(title)
    
    # 高亮表头
    colored_headers = [f"{Colors.BOLD}{h}{Colors.RESET}" for h in headers]
    
    # 打印表格
    print(tabulate(data, headers=colored_headers, tablefmt="pretty"))
    print()

def format_severity(severity: str) -> str:
    """
    格式化严重程度，添加颜色
    
    Args:
        severity: 严重程度
        
    Returns:
        str: 带颜色的严重程度
    """
    severity = severity.lower()
    if severity == "critical":
        return f"{Fore.RED}{Style.BRIGHT}严重{Style.RESET_ALL}"
    elif severity == "high":
        return f"{Fore.RED}高{Style.RESET_ALL}"
    elif severity == "medium":
        return f"{Fore.YELLOW}中{Style.RESET_ALL}"
    elif severity == "low":
        return f"{Fore.GREEN}低{Style.RESET_ALL}"
    else:
        return severity

def progress_bar(iterable, prefix='', suffix='', decimals=1, length=50, fill='█', print_end="\r"):
    """
    CLI进度条
    
    Args:
        iterable: 可迭代对象
        prefix: 前缀字符串
        suffix: 后缀字符串
        decimals: 百分比小数位数
        length: 进度条长度
        fill: 进度条填充字符
        print_end: 打印结束字符
    """
    total = len(iterable)
    
    def print_progress(iteration):
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filled_length = int(length * iteration // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{Colors.INFO}{prefix} |{bar}| {percent}% {suffix}{Colors.RESET}', end=print_end)
    
    print_progress(0)
    for i, item in enumerate(iterable):
        yield item
        print_progress(i + 1)
    print()

def confirm_action(message: str, default: bool = False) -> bool:
    """
    确认动作
    
    Args:
        message: 提示消息
        default: 默认选项
        
    Returns:
        bool: 用户确认结果
    """
    default_str = "Y/n" if default else "y/N"
    response = input(f"{Colors.WARNING}{message} [{default_str}]: {Colors.RESET}").strip().lower()
    
    if not response:
        return default
    
    return response[0] == 'y'

def load_config(config_path: Union[str, Path] = "config/sources.yml") -> Dict:
    """
    加载配置文件
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        Dict: 配置信息
    """
    from ..utils.file_utils import read_yaml
    
    try:
        return read_yaml(config_path)
    except Exception as e:
        print_error(f"加载配置文件失败: {e}")
        sys.exit(1)

def format_json(data: Dict, indent: int = 2) -> str:
    """
    格式化JSON
    
    Args:
        data: 要格式化的数据
        indent: 缩进空格数
        
    Returns:
        str: 格式化后的JSON字符串
    """
    return json.dumps(data, indent=indent, ensure_ascii=False)

def format_tags(tags: List[str]) -> str:
    """
    格式化标签列表
    
    Args:
        tags: 标签列表
        
    Returns:
        str: 格式化后的标签字符串
    """
    if not tags:
        return ""
    
    return ", ".join([f"{Colors.INFO}{tag}{Colors.RESET}" for tag in tags])