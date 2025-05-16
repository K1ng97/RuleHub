#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
版本管理命令模块
提供版本相关命令
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import argparse
from datetime import datetime

from ..utils.cli_utils import (
    print_success, print_error, print_warning, print_info, print_header,
    print_table, confirm_action
)
from ..wizard import VersionWizard
from tools.utils.file_utils import ensure_dir, read_json, write_json, list_files

from tools.cli import command

logger = logging.getLogger(__name__)

@command("version", "list", "列出版本历史")
def list_versions(args):
    """
    列出版本历史
    
    Args:
        args: 命令行参数
    """
    try:
        print_header("版本历史")
        
        # 获取版本目录
        versions_dir = Path(args.dir)
        if not versions_dir.exists():
            versions_dir.mkdir(parents=True, exist_ok=True)
            print_warning(f"版本目录不存在，已创建: {versions_dir}")
            print_info("尚无版本历史记录")
            return
        
        # 获取所有版本文件
        version_files = list(versions_dir.glob("v*.json"))
        if not version_files:
            print_info("尚无版本历史记录")
            return
        
        # 读取版本信息
        versions = []
        for file in version_files:
            try:
                version_data = read_json(file)
                versions.append(version_data)
            except Exception as e:
                print_warning(f"读取版本文件 {file} 失败: {e}")
        
        if not versions:
            print_error("读取版本信息失败")
            return
        
        # 按版本号排序
        versions.sort(key=lambda v: [int(x) for x in v["version"].split(".")], reverse=True)
        
        # 显示版本信息
        if args.format == "table" or not args.format:
            headers = ["版本", "发布日期", "说明"]
            rows = []
            
            for v in versions:
                version = v["version"]
                
                # 格式化日期
                date = v.get("release_date", "")
                if date:
                    try:
                        date = datetime.fromisoformat(date.replace("Z", "+00:00")).strftime("%Y-%m-%d")
                    except:
                        pass
                
                # 提取说明
                notes = v.get("release_notes", "")
                if len(notes) > 50:
                    notes = notes[:47] + "..."
                    
                rows.append([version, date, notes])
            
            print_table(headers, rows, f"版本历史 (共 {len(versions)} 个)")
            
        elif args.format == "full":
            print_header(f"版本历史 (共 {len(versions)} 个)")
            
            for v in versions:
                version = v["version"]
                date = v.get("release_date", "")
                if date:
                    try:
                        date = datetime.fromisoformat(date.replace("Z", "+00:00")).strftime("%Y-%m-%d")
                    except:
                        pass
                
                print(f"\n{Colors.BOLD}版本 {version} ({date}){Colors.RESET}")
                
                if v.get("release_notes"):
                    print(f"\n{v['release_notes']}")
                
                changes = v.get("changes", {})
                
                # 新增功能
                if changes.get("added"):
                    print(f"\n{Colors.SUCCESS}新增:{Colors.RESET}")
                    for item in changes["added"]:
                        print(f"- {item}")
                
                # 变更功能
                if changes.get("changed"):
                    print(f"\n{Colors.INFO}变更:{Colors.RESET}")
                    for item in changes["changed"]:
                        print(f"- {item}")
                
                # 修复问题
                if changes.get("fixed"):
                    print(f"\n{Colors.WARNING}修复:{Colors.RESET}")
                    for item in changes["fixed"]:
                        print(f"- {item}")
                
                # 移除功能
                if changes.get("removed"):
                    print(f"\n{Colors.ERROR}移除:{Colors.RESET}")
                    for item in changes["removed"]:
                        print(f"- {item}")
                
                print(f"\n{Colors.DIM}{'_' * 50}{Colors.RESET}")
                
        elif args.format == "json":
            # 以JSON格式直接输出到控制台
            print(json.dumps(versions, indent=2, ensure_ascii=False))
        
        # 保存到文件
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(versions, f, indent=2, ensure_ascii=False)
            print_success(f"版本历史已保存到: {args.output}")
            
    except Exception as e:
        print_error(f"列出版本历史时发生错误: {e}")
        logger.error(f"列出版本历史时发生错误: {e}", exc_info=True)

@command("version", "create", "创建新版本（交互式）")
def create_version(args):
    """
    创建新版本
    
    Args:
        args: 命令行参数
    """
    try:
        # 创建版本向导
        wizard = VersionWizard(args.dir)
        version_info = wizard.create_version()
        
        if version_info and args.changelog:
            # 生成变更日志
            wizard.generate_changelog(args.changelog)
            
    except Exception as e:
        print_error(f"创建版本时发生错误: {e}")
        logger.error(f"创建版本时发生错误: {e}", exc_info=True)

@command("version", "changelog", "生成变更日志")
def generate_changelog(args):
    """
    生成变更日志
    
    Args:
        args: 命令行参数
    """
    try:
        print_header("生成变更日志")
        
        # 创建版本向导
        wizard = VersionWizard(args.dir)
        success = wizard.generate_changelog(args.output)
        
        if success:
            print_success(f"变更日志已生成: {args.output}")
        else:
            print_error("生成变更日志失败")
            
    except Exception as e:
        print_error(f"生成变更日志时发生错误: {e}")
        logger.error(f"生成变更日志时发生错误: {e}", exc_info=True)

@command("version", "show", "显示特定版本的详细信息")
def show_version(args):
    """
    显示版本详细信息
    
    Args:
        args: 命令行参数
    """
    try:
        if not args.version:
            print_error("必须提供版本号")
            return
        
        print_header(f"版本详情: {args.version}")
        
        # 获取版本文件
        versions_dir = Path(args.dir)
        version_file = versions_dir / f"v{args.version}.json"
        
        if not version_file.exists():
            print_error(f"版本文件不存在: {version_file}")
            return
        
        # 读取版本信息
        try:
            version_data = read_json(version_file)
        except Exception as e:
            print_error(f"读取版本文件失败: {e}")
            return
        
        # 显示版本信息
        version = version_data["version"]
        date = version_data.get("release_date", "")
        if date:
            try:
                date = datetime.fromisoformat(date.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            except:
                pass
        
        print(f"{Colors.BOLD}版本: {version}{Colors.RESET}")
        print(f"发布日期: {date}")
        
        if version_data.get("release_notes"):
            print(f"\n说明:\n{version_data['release_notes']}")
        
        changes = version_data.get("changes", {})
        
        # 新增功能
        if changes.get("added"):
            print(f"\n{Colors.SUCCESS}新增:{Colors.RESET}")
            for item in changes["added"]:
                print(f"- {item}")
        
        # 变更功能
        if changes.get("changed"):
            print(f"\n{Colors.INFO}变更:{Colors.RESET}")
            for item in changes["changed"]:
                print(f"- {item}")
        
        # 修复问题
        if changes.get("fixed"):
            print(f"\n{Colors.WARNING}修复:{Colors.RESET}")
            for item in changes["fixed"]:
                print(f"- {item}")
        
        # 移除功能
        if changes.get("removed"):
            print(f"\n{Colors.ERROR}移除:{Colors.RESET}")
            for item in changes["removed"]:
                print(f"- {item}")
        
        # 保存到文件
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(version_data, f, indent=2, ensure_ascii=False)
            print_success(f"版本详情已保存到: {args.output}")
            
    except Exception as e:
        print_error(f"显示版本详情时发生错误: {e}")
        logger.error(f"显示版本详情时发生错误: {e}", exc_info=True)

# 引入颜色常量，避免命令文件中的引用错误
from ..utils.cli_utils import Colors