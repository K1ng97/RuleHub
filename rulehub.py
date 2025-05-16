#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RuleHub - 网络安全检测规则仓库系统
入口脚本，提供命令行接口

使用示例:
- 规则管理:        python3 rulehub.py rule [list|show|create|validate|test|update|delete]
- 仓库管理:        python3 rulehub.py repo [list|sync|add|update|remove]
- 索引管理:        python3 rulehub.py index [generate|search|stats]
- 版本管理:        python3 rulehub.py version [list|create|changelog]
- 显示帮助信息:    python3 rulehub.py --help
"""

import os
import sys
import logging
import argparse
import inspect
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import importlib
from colorama import init as colorama_init

# 初始化colorama
colorama_init(autoreset=True)

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('rulehub.log')
    ]
)
logger = logging.getLogger(__name__)

# 导入CLI组件
try:
    from tools.cli import registry, load_commands
    from tools.cli.utils.cli_utils import print_success, print_error, print_warning, print_info, print_header
except ImportError as e:
    logger.error("导入CLI组件失败: %s", str(e))
    print("Error: 导入CLI组件失败: {}".format(e))
    print("请确保已正确安装所有依赖项，或尝试运行: pip install -r requirements.txt")
    sys.exit(1)

def setup_argparser() -> argparse.ArgumentParser:
    """
    设置命令行参数解析器
    
    Returns:
        argparse.ArgumentParser: 参数解析器
    """
    parser = argparse.ArgumentParser(
        description="RuleHub - 网络安全检测规则仓库系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    # 列出所有规则
    python3 rulehub.py rule list
    
    # 显示特定规则详情
    python3 rulehub.py rule show --id RULE_ID
    
    # 创建新规则
    python3 rulehub.py rule create
    
    # 同步规则源
    python3 rulehub.py repo sync [--source SOURCE_NAME]
    
    # 生成规则索引
    python3 rulehub.py index generate
    
    # 搜索规则
    python3 rulehub.py index search --tags windows,lateral_movement
    
    # 显示规则统计
    python3 rulehub.py index stats
    
    # 创建新版本
    python3 rulehub.py version create
    """
    )
    
    # 加载命令注册表中的命令
    load_commands()
    
    # 根据注册的命令创建子解析器
    subparsers = parser.add_subparsers(dest="command_group", help="命令组")
    
    # 为每个命令组创建子解析器
    for group, commands in registry.get_all_commands().items():
        group_help = registry.get_command_groups().get(group, group)
        group_parser = subparsers.add_parser(group, help=group_help)
        group_subparsers = group_parser.add_subparsers(dest="command", help=f"{group}命令")
        
        # 为每个命令创建解析器
        for cmd_name, cmd_info in commands.items():
            cmd_parser = group_subparsers.add_parser(cmd_name, help=cmd_info["help"])
            
            # 获取命令函数的参数
            func = cmd_info["func"]
            sig = inspect.signature(func)
            parameters = sig.parameters
            
            # 检查函数是否接受args参数
            if "args" in parameters:
                # 根据命令添加特定参数
                if group == "rule":
                    if cmd_name == "list":
                        cmd_parser.add_argument("--id", help="按ID筛选规则")
                        cmd_parser.add_argument("--name", help="按名称筛选规则")
                        cmd_parser.add_argument("--tags", help="按标签筛选规则 (逗号分隔)")
                        cmd_parser.add_argument("--severity", help="按严重程度筛选规则")
                        cmd_parser.add_argument("--source", help="按规则源筛选规则")
                        cmd_parser.add_argument("--platform", help="按平台筛选规则 (逗号分隔)")
                        cmd_parser.add_argument("--output", "-o", help="输出结果到文件")
                    
                    elif cmd_name == "show":
                        cmd_parser.add_argument("--id", required=True, help="规则ID")
                        cmd_parser.add_argument("--output", "-o", help="输出结果到文件")
                    
                    elif cmd_name == "create":
                        cmd_parser.add_argument("--no-index", action="store_true", help="不更新索引")
                    
                    elif cmd_name == "validate":
                        validation_group = cmd_parser.add_mutually_exclusive_group()
                        validation_group.add_argument("--id", help="验证特定ID的规则")
                        validation_group.add_argument("--file", help="验证特定文件")
                        validation_group.add_argument("--dir", help="验证目录中的所有规则")
                        cmd_parser.add_argument("--output", "-o", help="输出验证报告到文件")
                    
                    elif cmd_name == "test":
                        cmd_parser.add_argument("--id", required=True, help="规则ID")
                        cmd_parser.add_argument("--sample", help="样例数据文件")
                    
                    elif cmd_name == "update":
                        cmd_parser.add_argument("--id", required=True, help="规则ID")
                        cmd_parser.add_argument("--name", help="更新规则名称")
                        cmd_parser.add_argument("--description", help="更新规则描述")
                        cmd_parser.add_argument("--severity", help="更新严重程度")
                        cmd_parser.add_argument("--tags", help="更新标签 (逗号分隔)")
                        cmd_parser.add_argument("--platforms", help="更新平台 (逗号分隔)")
                        cmd_parser.add_argument("--query", help="更新检测查询")
                        cmd_parser.add_argument("--status", help="更新规则状态")
                        cmd_parser.add_argument("--no-index", action="store_true", help="不更新索引")
                    
                    elif cmd_name == "delete":
                        cmd_parser.add_argument("--id", required=True, help="规则ID")
                        cmd_parser.add_argument("--force", action="store_true", help="强制删除，不提示确认")
                        cmd_parser.add_argument("--no-index", action="store_true", help="不更新索引")
                
                elif group == "repo":
                    if cmd_name == "list":
                        cmd_parser.add_argument("--config", "-c", default="config/sources.yml", help="配置文件路径")
                        cmd_parser.add_argument("--sort", help="排序字段 (name, type, status)")
                        cmd_parser.add_argument("--output", "-o", help="输出结果到文件")
                    
                    elif cmd_name == "sync":
                        cmd_parser.add_argument("--config", "-c", default="config/sources.yml", help="配置文件路径")
                        cmd_parser.add_argument("--source", "-s", help="仅同步指定的规则源")
                        cmd_parser.add_argument("--clean", action="store_true", help="同步后清理临时文件")
                    
                    elif cmd_name == "add":
                        cmd_parser.add_argument("--config", "-c", default="config/sources.yml", help="配置文件路径")
                        cmd_parser.add_argument("--name", required=True, help="规则源名称")
                        cmd_parser.add_argument("--url", required=True, help="仓库URL")
                        cmd_parser.add_argument("--branch", help="分支名称")
                        cmd_parser.add_argument("--type", help="规则类型")
                        cmd_parser.add_argument("--converter", help="转换器名称")
                        cmd_parser.add_argument("--format", help="规则格式")
                        cmd_parser.add_argument("--paths", help="规则路径 (逗号分隔)")
                        cmd_parser.add_argument("--force", action="store_true", help="强制覆盖现有配置")
                        cmd_parser.add_argument("--sync", action="store_true", help="添加后立即同步")
                    
                    elif cmd_name == "update":
                        cmd_parser.add_argument("--config", "-c", default="config/sources.yml", help="配置文件路径")
                        cmd_parser.add_argument("--name", required=True, help="规则源名称")
                        cmd_parser.add_argument("--url", help="更新仓库URL")
                        cmd_parser.add_argument("--branch", help="更新分支名称")
                        cmd_parser.add_argument("--type", help="更新规则类型")
                        cmd_parser.add_argument("--converter", help="更新转换器名称")
                        cmd_parser.add_argument("--format", help="更新规则格式")
                        cmd_parser.add_argument("--paths", help="更新规则路径 (逗号分隔)")
                        cmd_parser.add_argument("--enable", type=bool, help="启用或禁用规则源")
                        cmd_parser.add_argument("--sync", action="store_true", help="更新后立即同步")
                    
                    elif cmd_name == "remove":
                        cmd_parser.add_argument("--config", "-c", default="config/sources.yml", help="配置文件路径")
                        cmd_parser.add_argument("--name", required=True, help="规则源名称")
                        cmd_parser.add_argument("--force", action="store_true", help="强制删除，不提示确认")
                        cmd_parser.add_argument("--delete-rules", action="store_true", help="同时删除规则文件")
                
                elif group == "index":
                    if cmd_name == "generate":
                        cmd_parser.add_argument("--rules-dir", default="rules", help="规则目录")
                        cmd_parser.add_argument("--index-dir", default="index", help="索引目录")
                        cmd_parser.add_argument("--force", action="store_true", help="强制重建索引")
                        cmd_parser.add_argument("--verbose", "-v", action="store_true", help="显示详细输出")
                    
                    elif cmd_name == "search":
                        cmd_parser.add_argument("--id", help="按ID搜索")
                        cmd_parser.add_argument("--name", help="按名称搜索")
                        cmd_parser.add_argument("--description", help="按描述搜索")
                        cmd_parser.add_argument("--tags", help="按标签搜索 (逗号分隔)")
                        cmd_parser.add_argument("--severity", help="按严重程度搜索")
                        cmd_parser.add_argument("--platform", help="按平台搜索 (逗号分隔)")
                        cmd_parser.add_argument("--mitre-tactics", help="按MITRE战术搜索 (逗号分隔)")
                        cmd_parser.add_argument("--mitre-techniques", help="按MITRE技术搜索 (逗号分隔)")
                        cmd_parser.add_argument("--source", help="按规则源搜索")
                        cmd_parser.add_argument("--limit", type=int, help="限制结果数量")
                        cmd_parser.add_argument("--format", choices=["table", "full", "json"], help="输出格式")
                        cmd_parser.add_argument("--output", "-o", help="输出结果到文件")
                    
                    elif cmd_name == "stats":
                        cmd_parser.add_argument("--detailed", "-d", action="store_true", help="显示详细统计")
                        cmd_parser.add_argument("--output", "-o", help="输出结果到文件")
                
                elif group == "version":
                    if cmd_name == "list":
                        cmd_parser.add_argument("--dir", default="versions", help="版本目录")
                        cmd_parser.add_argument("--format", choices=["table", "full", "json"], help="输出格式")
                        cmd_parser.add_argument("--output", "-o", help="输出结果到文件")
                    
                    elif cmd_name == "create":
                        cmd_parser.add_argument("--dir", default="versions", help="版本目录")
                        cmd_parser.add_argument("--changelog", default="CHANGELOG.md", help="生成变更日志文件")
                    
                    elif cmd_name == "changelog":
                        cmd_parser.add_argument("--dir", default="versions", help="版本目录")
                        cmd_parser.add_argument("--output", "-o", default="CHANGELOG.md", help="输出文件路径")
                    
                    elif cmd_name == "show":
                        cmd_parser.add_argument("--dir", default="versions", help="版本目录")
                        cmd_parser.add_argument("--version", required=True, help="版本号")
                        cmd_parser.add_argument("--output", "-o", help="输出结果到文件")
    
    # 添加版本参数
    parser.add_argument("--version", "-v", action="store_true", help="显示版本信息")
    
    return parser

def main():
    """主函数"""
    parser = setup_argparser()
    args = parser.parse_args()
    
    if args.version:
        print("RuleHub 版本 1.0.0")
        print("网络安全检测规则仓库系统")
        print("Copyright (c) 2025")
        sys.exit(0)
    
    if args.command_group is None:
        parser.print_help()
        sys.exit(0)
    
    # 执行命令
    try:
        command_group = args.command_group
        command = getattr(args, "command", None)
        
        if command is None:
            # 只提供了命令组，显示该组的帮助
            for action in parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    for group_name, group_parser in action.choices.items():
                        if group_name == command_group:
                            group_parser.print_help()
                            break
            sys.exit(0)
        
        # 获取命令函数
        cmd_info = registry.get_command(command_group, command)
        if cmd_info is None:
            print_error("未知命令: {} {}".format(command_group, command))
            sys.exit(1)
        
        # 执行命令
        cmd_info["func"](args)
    
    except ImportError as e:
        print_error("导入模块失败: {}".format(e))
        logger.error("导入模块失败: %s", str(e), exc_info=True)
        sys.exit(1)
    except Exception as e:
        print_error("执行命令时发生错误: {}".format(e))
        logger.error("执行命令时发生错误: %s", str(e), exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()