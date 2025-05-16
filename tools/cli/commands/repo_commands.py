#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仓库管理命令模块
提供仓库相关命令
"""

import os
import sys
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import argparse
from datetime import datetime

from ..utils.cli_utils import (
    print_success, print_error, print_warning, print_info, print_header,
    print_table, progress_bar, confirm_action, load_config
)
from tools.sync.sync_manager import SyncManager
from tools.indexing.indexer import RuleIndexer
from tools.utils.file_utils import ensure_dir, read_yaml, write_yaml, list_files

from tools.cli import command

logger = logging.getLogger(__name__)

@command("repo", "list", "列出所有规则仓库")
def list_repos(args):
    """
    列出规则仓库
    
    Args:
        args: 命令行参数
    """
    try:
        # 加载配置
        config = load_config(args.config)
        sources = config.get("sources", {})
        
        if not sources:
            print_warning("未配置任何规则源")
            return
        
        # 准备表格数据
        headers = ["名称", "类型", "地址", "分支", "状态", "最后同步"]
        rows = []
        
        # 获取同步状态
        sync_stats = {}
        stats_path = Path("stats/sync_stats.json")
        if stats_path.exists():
            try:
                sync_stats = read_yaml(stats_path)
            except:
                sync_stats = {}
        
        # 构建表格行
        for name, source_config in sources.items():
            # 获取源状态
            enabled = source_config.get("enabled", True)
            status = f"{Colors.SUCCESS}启用{Colors.RESET}" if enabled else f"{Colors.ERROR}禁用{Colors.RESET}"
            
            # 获取最后同步时间
            last_sync = "从未"
            source_details = sync_stats.get("details", {}).get(name, {})
            if source_details:
                if "end_time" in source_details:
                    try:
                        sync_time = datetime.fromtimestamp(source_details["end_time"])
                        last_sync = sync_time.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        pass
            
            rows.append([
                name,
                source_config.get("type", "未知"),
                source_config.get("repo_url", "未设置"),
                source_config.get("branch", "main"),
                status,
                last_sync
            ])
        
        # 排序
        if args.sort:
            sort_column = args.sort.lower()
            sort_idx = None
            
            if sort_column == "name":
                sort_idx = 0
            elif sort_column == "type":
                sort_idx = 1
            elif sort_column == "status":
                sort_idx = 4
            
            if sort_idx is not None:
                rows.sort(key=lambda x: x[sort_idx])
        
        # 显示表格
        print_table(headers, rows, f"规则源列表 (共 {len(sources)} 个)")
        
        # 保存到文件
        if args.output:
            # 创建更详细的输出
            output_data = []
            for name, source_config in sources.items():
                source_data = {
                    "name": name,
                    "config": source_config,
                    "stats": sync_stats.get("details", {}).get(name, {})
                }
                output_data.append(source_data)
                
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            print_success(f"规则源列表已保存到: {args.output}")
            
    except Exception as e:
        print_error(f"列出规则源时发生错误: {e}")
        logger.error(f"列出规则源时发生错误: {e}", exc_info=True)

@command("repo", "sync", "手动同步规则仓库")
def sync_repo(args):
    """
    同步规则仓库
    
    Args:
        args: 命令行参数
    """
    try:
        print_header("规则同步")
        
        # 创建同步管理器
        sync_manager = SyncManager(args.config)
        
        if args.source:
            # 仅同步指定的规则源
            sources = sync_manager.config.get("sources", {})
            if args.source not in sources:
                print_error(f"规则源 {args.source} 不存在")
                return
            
            source_config = sources[args.source]
            
            print_info(f"开始同步规则源: {args.source}")
            result = sync_manager.sync_source(args.source, source_config)
            
            if result["success"]:
                print_success(f"规则源 {args.source} 同步成功")
                print(f"共处理 {result['total_rules']} 条规则，转换成功 {result['converted_rules']} 条，失败 {result['failed_rules']} 条")
                print(f"耗时: {result['duration']:.2f} 秒")
            else:
                print_error(f"规则源 {args.source} 同步失败: {result.get('error', '未知错误')}")
                return
        else:
            # 同步所有规则源
            print_info("开始同步所有规则源")
            stats = sync_manager.sync_all()
            
            print_success("所有规则源同步完成")
            print(f"共处理 {stats['total_sources']} 个规则源")
            print(f"成功: {stats['successful_sources']}, 失败: {stats['failed_sources']}")
            print(f"规则总数: {stats['total_rules']}, 转换成功: {stats['converted_rules']}, 转换失败: {stats['failed_rules']}")
            print(f"总耗时: {stats['duration']:.2f} 秒")
        
        # 清理临时文件
        if args.clean:
            print_info("清理临时文件...")
            sync_manager.clean_temp_files()
        
        # 生成索引
        print_info("生成规则索引...")
        indexer = RuleIndexer(sync_manager.rules_dir)
        index_stats = indexer.generate_index()
        
        if index_stats["success"]:
            print_success(f"索引生成成功，共 {index_stats['total_rules']} 条规则")
        else:
            print_error(f"索引生成失败: {index_stats.get('error', '未知错误')}")
            
    except Exception as e:
        print_error(f"同步规则源时发生错误: {e}")
        logger.error(f"同步规则源时发生错误: {e}", exc_info=True)

@command("repo", "add", "添加新的规则源")
def add_repo(args):
    """
    添加规则源
    
    Args:
        args: 命令行参数
    """
    try:
        print_header("添加规则源")
        
        # 加载配置
        config = load_config(args.config)
        sources = config.get("sources", {})
        
        # 检查源名称是否已存在
        if args.name in sources:
            if not args.force:
                print_error(f"规则源 {args.name} 已存在")
                print_warning("使用 --force 参数可以覆盖现有配置")
                return
            print_warning(f"将覆盖现有规则源: {args.name}")
        
        # 创建源配置
        source_config = {
            "repo_url": args.url,
            "branch": args.branch or "main",
            "type": args.type or "sigma",
            "converter": args.converter or args.name,
            "format": args.format or "yaml",
            "paths": args.paths.split(",") if args.paths else ["./"],
            "enabled": True
        }
        
        # 更新配置
        sources[args.name] = source_config
        config["sources"] = sources
        
        # 保存配置
        write_yaml(config, args.config)
        print_success(f"已添加规则源: {args.name}")
        
        # 是否立即同步
        if args.sync:
            print_info(f"开始同步规则源: {args.name}")
            sync_manager = SyncManager(args.config)
            result = sync_manager.sync_source(args.name, source_config)
            
            if result["success"]:
                print_success(f"规则源 {args.name} 同步成功")
                print(f"共处理 {result['total_rules']} 条规则，转换成功 {result['converted_rules']} 条，失败 {result['failed_rules']} 条")
                print(f"耗时: {result['duration']:.2f} 秒")
                
                # 生成索引
                print_info("生成规则索引...")
                indexer = RuleIndexer(sync_manager.rules_dir)
                indexer.generate_index()
            else:
                print_error(f"规则源 {args.name} 同步失败: {result.get('error', '未知错误')}")
            
    except Exception as e:
        print_error(f"添加规则源时发生错误: {e}")
        logger.error(f"添加规则源时发生错误: {e}", exc_info=True)

@command("repo", "update", "更新规则源配置")
def update_repo(args):
    """
    更新规则源配置
    
    Args:
        args: 命令行参数
    """
    try:
        print_header("更新规则源")
        
        # 加载配置
        config = load_config(args.config)
        sources = config.get("sources", {})
        
        # 检查源是否存在
        if args.name not in sources:
            print_error(f"规则源 {args.name} 不存在")
            return
        
        # 获取当前配置
        source_config = sources[args.name]
        
        # 更新配置
        updated = False
        
        if args.url:
            source_config["repo_url"] = args.url
            print_info(f"已更新仓库地址: {args.url}")
            updated = True
            
        if args.branch:
            source_config["branch"] = args.branch
            print_info(f"已更新分支: {args.branch}")
            updated = True
            
        if args.type:
            source_config["type"] = args.type
            print_info(f"已更新类型: {args.type}")
            updated = True
            
        if args.converter:
            source_config["converter"] = args.converter
            print_info(f"已更新转换器: {args.converter}")
            updated = True
            
        if args.format:
            source_config["format"] = args.format
            print_info(f"已更新格式: {args.format}")
            updated = True
            
        if args.paths:
            source_config["paths"] = args.paths.split(",")
            print_info(f"已更新路径: {args.paths}")
            updated = True
            
        if args.enable is not None:
            source_config["enabled"] = args.enable
            status = "启用" if args.enable else "禁用"
            print_info(f"已{status}规则源")
            updated = True
        
        if not updated:
            print_warning("未指定要更新的字段")
            return
        
        # 保存配置
        sources[args.name] = source_config
        config["sources"] = sources
        write_yaml(config, args.config)
        print_success(f"已更新规则源: {args.name}")
        
        # 是否立即同步
        if args.sync:
            print_info(f"开始同步规则源: {args.name}")
            sync_manager = SyncManager(args.config)
            result = sync_manager.sync_source(args.name, source_config)
            
            if result["success"]:
                print_success(f"规则源 {args.name} 同步成功")
                print(f"共处理 {result['total_rules']} 条规则，转换成功 {result['converted_rules']} 条，失败 {result['failed_rules']} 条")
                print(f"耗时: {result['duration']:.2f} 秒")
                
                # 生成索引
                print_info("生成规则索引...")
                indexer = RuleIndexer(sync_manager.rules_dir)
                indexer.generate_index()
            else:
                print_error(f"规则源 {args.name} 同步失败: {result.get('error', '未知错误')}")
            
    except Exception as e:
        print_error(f"更新规则源时发生错误: {e}")
        logger.error(f"更新规则源时发生错误: {e}", exc_info=True)

@command("repo", "remove", "移除规则源")
def remove_repo(args):
    """
    移除规则源
    
    Args:
        args: 命令行参数
    """
    try:
        print_header("移除规则源")
        
        # 加载配置
        config = load_config(args.config)
        sources = config.get("sources", {})
        
        # 检查源是否存在
        if args.name not in sources:
            print_error(f"规则源 {args.name} 不存在")
            return
        
        # 确认删除
        if not args.force:
            if not confirm_action(f"确认移除规则源 {args.name}?", False):
                print_warning("已取消移除规则源")
                return
        
        # 移除源
        del sources[args.name]
        config["sources"] = sources
        
        # 保存配置
        write_yaml(config, args.config)
        print_success(f"已移除规则源: {args.name}")
        
        # 是否同时删除规则
        if args.delete_rules:
            rules_dir = Path("rules") / args.name
            if rules_dir.exists():
                import shutil
                shutil.rmtree(rules_dir)
                print_success(f"已删除规则目录: {rules_dir}")
                
                # 重新生成索引
                print_info("生成规则索引...")
                indexer = RuleIndexer()
                indexer.generate_index()
            
    except Exception as e:
        print_error(f"移除规则源时发生错误: {e}")
        logger.error(f"移除规则源时发生错误: {e}", exc_info=True)

# 引入颜色常量，避免命令文件中的引用错误
from ..utils.cli_utils import Colors