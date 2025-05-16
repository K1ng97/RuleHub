#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试同步过程的脚本
"""

import os
import logging
from pathlib import Path
from tools.sync.sync_manager import SyncManager
from tools.utils.file_utils import list_files

# 设置日志级别
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def debug_sync():
    # 创建同步管理器
    sync_manager = SyncManager()
    
    # 获取sigma配置
    source_name = 'sigma'
    source_config = sync_manager.config['sources'][source_name]
    print(f'规则源配置: {source_config}')
    
    # 获取仓库信息
    repo_url = source_config.get('repo_url')
    branch = source_config.get('branch', 'main')
    
    # 克隆仓库
    success, repo_info = sync_manager.repo_handler.clone_repo(source_name, repo_url, branch)
    
    if success and repo_info:
        # 获取规则路径和格式
        rule_paths = source_config.get('paths', [])
        rule_format = source_config.get('format', 'yaml')
        print(f'规则格式: {rule_format}')
        
        # 检查每个路径
        for path in rule_paths:
            full_path = repo_info.local_path / path
            print(f'检查路径: {full_path}, 存在: {full_path.exists()}')
            
            # 获取匹配模式
            pattern = f"*.{rule_format}"
            if rule_format == "yml":
                pattern = "*.{yml,yaml}"
            print(f'匹配模式: {pattern}')
            
            # 获取规则文件
            rule_files = list_files(full_path, pattern)
            print(f'找到规则文件数: {len(rule_files)}')
            
            if rule_files:
                print(f'第一个规则文件: {rule_files[0]}')
            
            # 检查一下yaml文件
            yml_files = list(full_path.glob("**/*.yml"))
            yaml_files = list(full_path.glob("**/*.yaml"))
            print(f"直接查找 - yml文件数: {len(yml_files)}, yaml文件数: {len(yaml_files)}")

if __name__ == "__main__":
    debug_sync()