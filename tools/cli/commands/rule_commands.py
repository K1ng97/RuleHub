#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则管理命令模块
提供规则相关命令
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
    print_table, format_severity, format_tags, progress_bar
)
from ..wizard import RuleWizard
from tools.indexing.indexer import RuleIndexer
from tools.validation.validator import RuleValidator
from tools.utils.file_utils import (
    ensure_dir, read_json, write_json, list_files
)

from tools.cli import command

logger = logging.getLogger(__name__)

@command("rule", "list", "列出所有规则或按条件筛选规则")
def list_rules(args):
    """
    列出规则
    
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
        
        if args.tags:
            query["tags"] = args.tags.split(",")
        
        if args.severity:
            query["severity"] = args.severity
        
        if args.source:
            query["source_type"] = args.source
        
        if args.platform:
            query["platforms"] = args.platform.split(",")
        
        # 搜索规则
        print_info("正在搜索规则...")
        results = indexer.search_rules(query)
        
        if not results:
            print_warning("未找到匹配的规则")
            return
        
        # 格式化输出
        headers = ["ID", "名称", "严重程度", "标签", "来源"]
        rows = []
        
        for rule in results:
            rows.append([
                rule["id"],
                rule["name"],
                format_severity(rule["severity"]),
                format_tags(rule.get("tags", [])[:3]),  # 仅显示前3个标签
                rule.get("source", {}).get("type", "未知")
            ])
        
        print_table(headers, rows, f"规则列表 (共 {len(results)} 条)")
        
        # 保存到文件
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print_success(f"规则列表已保存到: {args.output}")
            
    except Exception as e:
        print_error(f"列出规则时发生错误: {e}")
        logger.error(f"列出规则时发生错误: {e}", exc_info=True)

@command("rule", "show", "显示特定规则的详细信息")
def show_rule(args):
    """
    显示规则详细信息
    
    Args:
        args: 命令行参数
    """
    try:
        if not args.id:
            print_error("必须提供规则ID")
            return
        
        # 创建索引生成器
        indexer = RuleIndexer()
        
        # 通过ID查找规则
        rules = indexer.search_rules({"id": args.id})
        
        if not rules:
            print_error(f"找不到ID为 {args.id} 的规则")
            return
        
        rule = rules[0]
        
        # 读取完整规则文件
        rule_path = Path(rule["rule_path"])
        if not rule_path.exists():
            print_error(f"规则文件不存在: {rule_path}")
            return
        
        full_rule = read_json(rule_path)
        
        # 显示规则详细信息
        print_header(f"规则详情: {rule['name']}")
        print(f"ID: {Colors.BOLD}{rule['id']}{Colors.RESET}")
        print(f"名称: {rule['name']}")
        print(f"严重程度: {format_severity(rule['severity'])}")
        print(f"来源: {rule.get('source', {}).get('type', '未知')}")
        
        if "description" in rule:
            print("\n描述:")
            print(f"  {rule['description']}")
        
        if "tags" in rule and rule["tags"]:
            print("\n标签:")
            print(f"  {', '.join(rule['tags'])}")
        
        if "platforms" in rule and rule["platforms"]:
            print("\n适用平台:")
            print(f"  {', '.join(rule['platforms'])}")
        
        if "mitre" in rule:
            mitre = rule["mitre"]
            if "tactics" in mitre and mitre["tactics"]:
                print("\nMITRE战术:")
                print(f"  {', '.join(mitre['tactics'])}")
            
            if "techniques" in mitre and mitre["techniques"]:
                print("\nMITRE技术:")
                print(f"  {', '.join(mitre['techniques'])}")
        
        if "detection" in full_rule:
            detection = full_rule["detection"]
            print("\n检测查询:")
            if "query" in detection:
                print(f"{Colors.INFO}{detection['query']}{Colors.RESET}")
        
        if "created" in rule:
            print(f"\n创建时间: {rule['created']}")
        
        if "modified" in rule:
            print(f"修改时间: {rule['modified']}")
        
        # 保存到文件
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(full_rule, f, indent=2, ensure_ascii=False)
            print_success(f"规则详情已保存到: {args.output}")
            
    except Exception as e:
        print_error(f"显示规则详情时发生错误: {e}")
        logger.error(f"显示规则详情时发生错误: {e}", exc_info=True)

@command("rule", "create", "创建新规则（提供交互式向导）")
def create_rule(args):
    """
    创建新规则
    
    Args:
        args: 命令行参数
    """
    try:
        wizard = RuleWizard()
        rule = wizard.create_rule()
        
        if rule:
            # 重新生成索引
            if not args.no_index:
                print_info("正在更新索引...")
                indexer = RuleIndexer()
                indexer.generate_index()
                print_success("索引已更新")
        
    except Exception as e:
        print_error(f"创建规则时发生错误: {e}")
        logger.error(f"创建规则时发生错误: {e}", exc_info=True)

@command("rule", "validate", "验证规则的语法和格式")
def validate_rule(args):
    """
    验证规则
    
    Args:
        args: 命令行参数
    """
    try:
        # 获取规则文件
        rule_files = []
        
        if args.id:
            # 通过ID查找规则
            indexer = RuleIndexer()
            rules = indexer.search_rules({"id": args.id})
            
            if not rules:
                print_error(f"找不到ID为 {args.id} 的规则")
                return
            
            for rule in rules:
                rule_path = Path(rule["rule_path"])
                if rule_path.exists():
                    rule_files.append(rule_path)
        
        elif args.file:
            # 使用指定文件
            rule_file = Path(args.file)
            if not rule_file.exists():
                print_error(f"规则文件不存在: {rule_file}")
                return
            
            rule_files.append(rule_file)
        
        elif args.dir:
            # 扫描目录
            rule_dir = Path(args.dir)
            if not rule_dir.exists() or not rule_dir.is_dir():
                print_error(f"规则目录不存在: {rule_dir}")
                return
            
            rule_files.extend(list_files(rule_dir, "*.json"))
        
        else:
            # 默认使用规则目录
            rules_dir = Path("rules")
            if not rules_dir.exists():
                print_error(f"规则目录不存在: {rules_dir}")
                return
            
            for source_dir in rules_dir.iterdir():
                if source_dir.is_dir():
                    rule_files.extend(list_files(source_dir, "*.json"))
        
        if not rule_files:
            print_warning("没有找到规则文件")
            return
        
        print_info(f"开始验证 {len(rule_files)} 个规则文件...")
        
        # 创建验证器
        validator = RuleValidator(args.output or "validation_report.json")
        
        # 验证规则
        report = validator.validate_files(rule_files)
        
        # 输出结果
        print_header("验证结果")
        
        print(f"总规则数: {report['total_rules']}")
        print(f"通过: {Colors.SUCCESS}{report['passed_rules']}{Colors.RESET}")
        print(f"失败: {Colors.ERROR}{report['failed_rules']}{Colors.RESET}")
        
        if report["errors"]:
            print_header("错误详情")
            
            for error in report["errors"]:
                print(f"{Colors.ERROR}[错误]{Colors.RESET} 文件: {error['file']}")
                print(f"  规则ID: {error['rule_id']}")
                print(f"  错误信息: {error['message']}")
                print()
        
        if report["warnings"]:
            print_header("警告详情")
            
            for warning in report["warnings"]:
                print(f"{Colors.WARNING}[警告]{Colors.RESET} 文件: {warning['file']}")
                print(f"  规则ID: {warning['rule_id']}")
                print(f"  警告信息: {warning['message']}")
                print()
        
        if args.output:
            print_success(f"验证报告已保存到: {args.output}")
            
    except Exception as e:
        print_error(f"验证规则时发生错误: {e}")
        logger.error(f"验证规则时发生错误: {e}", exc_info=True)

@command("rule", "test", "使用样例数据测试规则")
def test_rule(args):
    """
    测试规则
    
    Args:
        args: 命令行参数
    """
    try:
        if not args.id:
            print_error("必须提供规则ID")
            return
        
        # 通过ID查找规则
        indexer = RuleIndexer()
        rules = indexer.search_rules({"id": args.id})
        
        if not rules:
            print_error(f"找不到ID为 {args.id} 的规则")
            return
        
        rule = rules[0]
        rule_path = Path(rule["rule_path"])
        
        if not rule_path.exists():
            print_error(f"规则文件不存在: {rule_path}")
            return
        
        # 读取规则
        full_rule = read_json(rule_path)
        
        # 获取样例数据
        samples_dir = Path("samples")
        sample_file = None
        
        if args.sample:
            sample_file = Path(args.sample)
            if not sample_file.exists():
                print_error(f"样例文件不存在: {sample_file}")
                return
        else:
            # 尝试查找匹配的样例文件
            if samples_dir.exists():
                potential_samples = list(samples_dir.glob(f"{args.id}_*.json")) or list(samples_dir.glob(f"*_{args.id}.json"))
                if potential_samples:
                    sample_file = potential_samples[0]
        
        if not sample_file:
            print_warning(f"未找到规则 {args.id} 的样例数据文件")
            print_info("请使用 --sample 参数指定样例数据文件")
            return
        
        # 读取样例数据
        try:
            sample_data = read_json(sample_file)
        except Exception as e:
            print_error(f"读取样例数据失败: {e}")
            return
        
        print_header(f"测试规则: {rule['name']}")
        print(f"规则ID: {rule['id']}")
        print(f"样例文件: {sample_file}")
        
        # 检查规则类型和执行测试
        rule_type = full_rule.get("source", {}).get("type", "")
        
        if rule_type == "sigma":
            print_info("\n使用Sigma规则测试...")
            _test_sigma_rule(full_rule, sample_data)
        else:
            print_warning(f"不支持的规则类型: {rule_type}")
        
    except Exception as e:
        print_error(f"测试规则时发生错误: {e}")
        logger.error(f"测试规则时发生错误: {e}", exc_info=True)

def _test_sigma_rule(rule: Dict, sample_data: Dict):
    """
    测试Sigma规则
    
    Args:
        rule: 规则数据
        sample_data: 样例数据
    """
    # 这里仅为示例，实际实现需要根据规则引擎来执行
    print_warning("Sigma规则测试功能尚未完全实现")
    print_info("规则查询:")
    detection = rule.get("detection", {})
    if "query" in detection:
        print(f"{Colors.INFO}{detection['query']}{Colors.RESET}")
    
    print_info("\n样例数据:")
    print(json.dumps(sample_data, indent=2, ensure_ascii=False))
    
    # 模拟测试结果
    print_success("\n测试通过 (模拟结果)")

@command("rule", "update", "更新现有规则")
def update_rule(args):
    """
    更新规则
    
    Args:
        args: 命令行参数
    """
    try:
        if not args.id:
            print_error("必须提供规则ID")
            return
        
        # 通过ID查找规则
        indexer = RuleIndexer()
        rules = indexer.search_rules({"id": args.id})
        
        if not rules:
            print_error(f"找不到ID为 {args.id} 的规则")
            return
        
        rule = rules[0]
        rule_path = Path(rule["rule_path"])
        
        if not rule_path.exists():
            print_error(f"规则文件不存在: {rule_path}")
            return
        
        # 读取规则
        full_rule = read_json(rule_path)
        
        print_header(f"更新规则: {rule['name']}")
        print(f"规则ID: {rule['id']}")
        print()
        
        # 更新规则字段
        updated = False
        
        if args.name:
            full_rule["name"] = args.name
            print_info(f"已更新名称: {args.name}")
            updated = True
        
        if args.description:
            full_rule["description"] = args.description
            print_info(f"已更新描述: {args.description}")
            updated = True
            
        if args.severity:
            if args.severity not in ["low", "medium", "high", "critical"]:
                print_warning(f"无效的严重程度: {args.severity}，应为 low/medium/high/critical 之一")
            else:
                full_rule["severity"] = args.severity
                print_info(f"已更新严重程度: {args.severity}")
                updated = True
                
        if args.tags:
            tags = [tag.strip() for tag in args.tags.split(",")]
            full_rule["tags"] = tags
            print_info(f"已更新标签: {', '.join(tags)}")
            updated = True
            
        if args.platforms:
            platforms = [p.strip() for p in args.platforms.split(",")]
            full_rule["platforms"] = platforms
            print_info(f"已更新平台: {', '.join(platforms)}")
            updated = True
        
        if args.query:
            if "detection" not in full_rule:
                full_rule["detection"] = {}
            full_rule["detection"]["query"] = args.query
            print_info("已更新查询")
            updated = True
        
        if args.status:
            full_rule["status"] = args.status
            print_info(f"已更新状态: {args.status}")
            updated = True
        
        if updated:
            # 更新修改时间
            full_rule["modified"] = datetime.now().isoformat()
            
            # 保存规则
            write_json(full_rule, rule_path)
            print_success(f"规则已更新: {rule_path}")
            
            # 重新生成索引
            if not args.no_index:
                print_info("正在更新索引...")
                indexer = RuleIndexer()
                indexer.generate_index()
                print_success("索引已更新")
        else:
            print_warning("未指定要更新的字段")
        
    except Exception as e:
        print_error(f"更新规则时发生错误: {e}")
        logger.error(f"更新规则时发生错误: {e}", exc_info=True)

@command("rule", "delete", "删除规则")
def delete_rule(args):
    """
    删除规则
    
    Args:
        args: 命令行参数
    """
    try:
        if not args.id:
            print_error("必须提供规则ID")
            return
        
        # 通过ID查找规则
        indexer = RuleIndexer()
        rules = indexer.search_rules({"id": args.id})
        
        if not rules:
            print_error(f"找不到ID为 {args.id} 的规则")
            return
        
        rule = rules[0]
        rule_path = Path(rule["rule_path"])
        
        if not rule_path.exists():
            print_error(f"规则文件不存在: {rule_path}")
            return
        
        print_header(f"删除规则: {rule['name']}")
        print(f"规则ID: {rule['id']}")
        print(f"规则路径: {rule_path}")
        
        # 确认删除
        if not args.force:
            confirmation = input(f"{Colors.WARNING}确认删除此规则? [y/N]: {Colors.RESET}")
            if confirmation.lower() != 'y':
                print_warning("已取消删除")
                return
        
        # 删除规则文件
        os.remove(rule_path)
        print_success(f"规则已删除: {rule_path}")
        
        # 重新生成索引
        if not args.no_index:
            print_info("正在更新索引...")
            indexer = RuleIndexer()
            indexer.generate_index()
            print_success("索引已更新")
        
    except Exception as e:
        print_error(f"删除规则时发生错误: {e}")
        logger.error(f"删除规则时发生错误: {e}", exc_info=True)

# 引入颜色常量，避免命令文件中的引用错误
from ..utils.cli_utils import Colors