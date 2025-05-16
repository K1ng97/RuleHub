#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI模块入口
负责加载和管理所有CLI命令
"""

import os
import sys
import logging
from typing import Dict, List, Any, Optional, Callable
import importlib
import inspect

# 设置日志
logger = logging.getLogger(__name__)

# 命令组映射
COMMAND_GROUPS = {
    "rule": "规则管理",
    "repo": "仓库管理",
    "index": "索引管理",
    "version": "版本管理"
}

class CommandRegistry:
    """命令注册表类，管理所有可用命令"""
    
    def __init__(self):
        self.commands = {}
        self.command_groups = {}
    
    def register_command(self, group: str, name: str, func: Callable, help_text: str) -> None:
        """
        注册命令
        
        Args:
            group: 命令组
            name: 命令名称
            func: 命令函数
            help_text: 帮助文本
        """
        if group not in self.commands:
            self.commands[group] = {}
            self.command_groups[group] = COMMAND_GROUPS.get(group, group)
            
        self.commands[group][name] = {
            "func": func,
            "help": help_text
        }
        
        logger.debug(f"已注册命令: {group} {name}")
    
    def get_command(self, group: str, name: str) -> Optional[Dict]:
        """
        获取命令
        
        Args:
            group: 命令组
            name: 命令名称
            
        Returns:
            Optional[Dict]: 命令信息
        """
        if group not in self.commands:
            return None
            
        return self.commands[group].get(name)
    
    def get_all_commands(self) -> Dict:
        """
        获取所有命令
        
        Returns:
            Dict: 命令信息
        """
        return self.commands
    
    def get_command_groups(self) -> Dict:
        """
        获取命令组
        
        Returns:
            Dict: 命令组信息
        """
        return self.command_groups

# 创建全局命令注册表
registry = CommandRegistry()

# 从命令模块加载命令
def load_commands():
    """加载所有命令"""
    logger.debug("加载命令模块...")
    
    # 命令模块列表
    command_modules = [
        "tools.cli.commands.rule_commands",
        "tools.cli.commands.repo_commands",
        "tools.cli.commands.index_commands",
        "tools.cli.commands.version_commands"
    ]
    
    for module_name in command_modules:
        try:
            module = importlib.import_module(module_name)
            logger.debug(f"已加载模块: {module_name}")
        except ImportError as e:
            logger.warning(f"加载模块 {module_name} 失败: {e}")

# 命令注册器装饰器
def command(group: str, name: str, help_text: str):
    """
    命令注册器装饰器
    
    Args:
        group: 命令组
        name: 命令名称
        help_text: 帮助文本
        
    Returns:
        Callable: 装饰器函数
    """
    def decorator(func):
        registry.register_command(group, name, func, help_text)
        return func
    return decorator