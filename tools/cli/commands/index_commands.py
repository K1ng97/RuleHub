#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
索引管理命令模块
提供索引相关命令
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import argparse
from datetime import datetime
import shutil

from ..utils.cli_utils import (
    print_success, print_error, print_warning, print_info, print_header,
    print_table, format_severity, format_tags, progress_bar, confirm_action
)
from tools.indexing.indexer import RuleIndexer
from tools.utils.file_utils import (
    ensure_dir, read_json, write_json, list_files
)

from tools.cli import command

logger = logging.getLogger(__name__)

@command("index", "generate", "生成或更新索引")
def generate_index(args):
    """
    生成索引
    
    Args:
        args: 命令行参数
    """
    try:
        print_header("生成规则索引")
        
        # 创建索引生成器
        indexer = RuleIndexer(args.rules_dir, args.index_dir)
        
        # 检查是否需要强制重建
        if args.force:
            # 删除现有索引文件
            index_dir = Path(args.index_dir)
            if index_dir.exists():
                print_warning(f"强制重建索引，正在删除: {index_dir}")
                
                for file in index_dir.glob("*.json"):
                    file.unlink()
                    
                print_info("已删除现有索引文件")
        
        # 生成索引
        print_info("正在生成索引...")
        start_time = datetime.now()
        stats = indexer.generate_index()
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        if stats["success"]:
            print_success(f"索引生成成功，共 {stats['total_rules']} 条规则")
            print(f"来自 {stats['total_sources']} 个规则源")
            print(f"耗时: {duration:.2f} 秒")
            
            # 显示规则源详情
            if args.verbose:
                print_header("规则源详情")
                headers = ["规则源", "规则数量"]
                rows = []
                
                for source, details in stats.get("source_stats", {}).items():
                    rows.append([source, details.get("rules_count", 0)])
                
                # 按规则数量排序
                rows.sort(key=lambda x: x[1], reverse=True)
                
                print_table(headers, rows)
        else:
            print_error(f"索引生成失败: {stats.get('error', '未知错误')}")
            
    except Exception as e:
        print_error(f"生成索引时发生错误: {e}")
        logger.error(f"生成索引时发生错误: {e}", exc_info=True)

@command("index", "search", "搜索规则（支持多种条件）")
def search_index(args):
    """
    搜索索引
    
    Args:
        args: 命令行参数
    """
    try:
        # 创建索引生成器
        indexer = RuleIndexer()
        
        # 构建查询条件
        query = {}
        
        if args.id:
            query["id"] = args.id
        
        if args.name:
            query["name"] = args.name
        
        if args.description:
            query["description"] = args.description
        
        if args.tags:
            query["tags"] = args.tags.split(",")
        
        if args.severity:
            query["severity"] = args.severity
        
        if args.platform:
            query["platforms"] = args.platform.split(",")
        
        if args.mitre_tactics:
            query["mitre_tactics"] = args.mitre_tactics.split(",")
        
        if args.mitre_techniques:
            query["mitre_techniques"] = args.mitre_techniques.split(",")
        
        if args.source:
            query["source_type"] = args.source
        
        # 搜索规则
        print_header("规则搜索")
        print_info("正在搜索规则...")
        results = indexer.search_rules(query)
        
        if not results:
            print_warning("未找到匹配的规则")
            return
        
        # 限制结果数量
        if args.limit and len(results) > args.limit:
            results = results[:args.limit]
            print_warning(f"结果已限制为 {args.limit} 条")
        
        # 格式化输出
        if args.format == "table" or not args.format:
            headers = ["ID", "名称", "严重程度", "标签", "规则源"]
            rows = []
            
            for rule in results:
                rows.append([
                    rule["id"],
                    rule["name"],
                    format_severity(rule["severity"]),
                    format_tags(rule.get("tags", [])[:3]),  # 仅显示前3个标签
                    rule.get("source", {}).get("type", "未知")
                ])
            
            print_table(headers, rows, f"搜索结果 (共 {len(results)} 条)")
        
        elif args.format == "full":
            print_header(f"搜索结果 (共 {len(results)} 条)")
            
            for i, rule in enumerate(results, 1):
                print(f"\n{Colors.BOLD}[{i}] {rule['name']} (ID: {rule['id']}){Colors.RESET}")
                print(f"严重程度: {format_severity(rule['severity'])}")
                print(f"规则源: {rule.get('source', {}).get('type', '未知')}")
                
                if "description" in rule:
                    print(f"描述: {rule['description']}")
                
                if "tags" in rule and rule["tags"]:
                    print(f"标签: {', '.join(rule['tags'])}")
                
                if "platforms" in rule and rule["platforms"]:
                    print(f"平台: {', '.join(rule['platforms'])}")
                
                if "mitre" in rule:
                    mitre = rule["mitre"]
                    if "tactics" in mitre and mitre["tactics"]:
                        print(f"MITRE战术: {', '.join(mitre['tactics'])}")
                    
                    if "techniques" in mitre and mitre["techniques"]:
                        print(f"MITRE技术: {', '.join(mitre['techniques'])}")
                
                print(f"文件路径: {rule['rule_path']}")
                print(f"{Colors.DIM}{'_' * 50}{Colors.RESET}")
        
        elif args.format == "json":
            # 以JSON格式直接输出到控制台
            print(json.dumps(results, indent=2, ensure_ascii=False))
        
        # 保存到文件
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print_success(f"搜索结果已保存到: {args.output}")
            
    except Exception as e:
        print_error(f"搜索规则时发生错误: {e}")
        logger.error(f"搜索规则时发生错误: {e}", exc_info=True)

@command("index", "stats", "显示规则统计信息")
def index_stats(args):
    """
    显示索引统计信息
    
    Args:
        args: 命令行参数
    """
    try:
        print_header("规则统计信息")
        
        # 获取索引统计信息
        stats_path = Path("index/index_stats.json")
        if not stats_path.exists():
            print_error("索引统计文件不存在")
            print_info("请先运行 'rulehub index generate' 生成索引")
            return
        
        try:
            stats = read_json(stats_path)
        except Exception as e:
            print_error(f"读取索引统计文件失败: {e}")
            return
        
        # 显示基本统计信息
        print(f"总规则数: {stats['total_rules']}")
        print(f"规则源数: {stats['total_sources']}")
        print(f"生成时间: {stats['start_time']}")
        print(f"生成耗时: {stats['duration']:.2f} 秒")
        
        # 显示规则源详情
        print_header("规则源统计")
        
        headers = ["规则源", "规则数量", "百分比"]
        rows = []
        
        source_stats = stats.get("source_stats", {})
        total_rules = stats["total_rules"]
        
        for source, details in source_stats.items():
            count = details.get("rules_count", 0)
            percent = (count / total_rules * 100) if total_rules > 0 else 0
            rows.append([source, count, f"{percent:.1f}%"])
        
        # 按规则数量排序
        rows.sort(key=lambda x: x[1], reverse=True)
        
        print_table(headers, rows)
        
        # 显示严重程度统计
        if args.detailed:
            # 读取完整索引以获取更多统计信息
            index_path = Path("index/rules_index.json")
            if not index_path.exists():
                print_warning("找不到完整索引文件，无法显示详细统计")
                return
            
            try:
                index = read_json(index_path)
                rules = index.get("rules", [])
            except Exception as e:
                print_error(f"读取索引文件失败: {e}")
                return
            
            print_header("严重程度统计")
            
            severity_stats = {}
            for rule in rules:
                severity = rule.get("severity", "unknown")
                severity_stats[severity] = severity_stats.get(severity, 0) + 1
            
            sev_headers = ["严重程度", "规则数量", "百分比"]
            sev_rows = []
            
            for severity, count in severity_stats.items():
                percent = (count / total_rules * 100) if total_rules > 0 else 0
                sev_rows.append([format_severity(severity), count, f"{percent:.1f}%"])
            
            sev_rows.sort(key=lambda x: {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3
            }.get(x[0].lower().strip(), 99))
            
            print_table(sev_headers, sev_rows)
            
            # 显示标签统计
            print_header("热门标签统计")
            
            tag_stats = {}
            for rule in rules:
                for tag in rule.get("tags", []):
                    tag_stats[tag] = tag_stats.get(tag, 0) + 1
            
            tag_headers = ["标签", "规则数量", "百分比"]
            tag_rows = []
            
            # 取前15个标签
            for tag, count in sorted(tag_stats.items(), key=lambda x: x[1], reverse=True)[:15]:
                percent = (count / total_rules * 100) if total_rules > 0 else 0
                tag_rows.append([tag, count, f"{percent:.1f}%"])
            
            print_table(tag_headers, tag_rows)
            
            # 显示MITRE统计
            print_header("MITRE ATT&CK战术统计")
            
            tactic_stats = {}
            for rule in rules:
                mitre = rule.get("mitre", {})
                for tactic in mitre.get("tactics", []):
                    tactic_stats[tactic] = tactic_stats.get(tactic, 0) + 1
            
            tactic_headers = ["战术", "规则数量", "百分比"]
            tactic_rows = []
            
            for tactic, count in sorted(tactic_stats.items(), key=lambda x: x[1], reverse=True):
                percent = (count / total_rules * 100) if total_rules > 0 else 0
                tactic_rows.append([tactic, count, f"{percent:.1f}%"])
            
            print_table(tactic_headers, tactic_rows)
        
        # 保存到文件
        if args.output:
            # 创建更详细的输出
            output_data = {
                "basic": {
                    "total_rules": stats["total_rules"],
                    "total_sources": stats["total_sources"],
                    "start_time": stats["start_time"],
                    "end_time": stats["end_time"],
                    "duration": stats["duration"]
                },
                "sources": {}
            }
            
            for source, details in source_stats.items():
                output_data["sources"][source] = details
            
            # 添加额外的统计信息
            if args.detailed and "rules" in locals():
                # 严重程度统计
                output_data["severity"] = {}
                for severity, count in severity_stats.items():
                    output_data["severity"][severity] = count
                
                # 标签统计
                output_data["tags"] = {}
                for tag, count in sorted(tag_stats.items(), key=lambda x: x[1], reverse=True):
                    output_data["tags"][tag] = count
                
                # MITRE统计
                output_data["mitre_tactics"] = {}
                for tactic, count in sorted(tactic_stats.items(), key=lambda x: x[1], reverse=True):
                    output_data["mitre_tactics"][tactic] = count
            
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            print_success(f"统计信息已保存到: {args.output}")
            
    except Exception as e:
        print_error(f"显示统计信息时发生错误: {e}")
        logger.error(f"显示统计信息时发生错误: {e}", exc_info=True)

# 引入颜色常量，避免命令文件中的引用错误
from ..utils.cli_utils import Colors