#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则索引生成器
负责生成规则索引文件
"""

import os
import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set
import jsonschema

from ..utils.file_utils import (
    ensure_dir, read_json, write_json, 
    list_files, get_file_hash
)

logger = logging.getLogger(__name__)

# 索引模式定义
INDEX_SCHEMA = {
    "type": "object",
    "properties": {
        "meta": {
            "type": "object",
            "properties": {
                "version": {"type": "string"},
                "generated_at": {"type": "string", "format": "date-time"},
                "total_rules": {"type": "integer"},
                "sources": {"type": "object"}
            },
            "required": ["version", "generated_at", "total_rules"]
        },
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "source": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string"},
                            "id": {"type": "string"}
                        },
                        "required": ["type"]
                    },
                    "severity": {"type": "string"},
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "platforms": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "mitre": {
                        "type": "object",
                        "properties": {
                            "tactics": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "techniques": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    },
                    "created": {"type": "string"},
                    "modified": {"type": "string"},
                    "rule_path": {"type": "string"}
                },
                "required": ["id", "name", "source", "rule_path"]
            }
        }
    },
    "required": ["meta", "rules"]
}


class RuleIndexer:
    """规则索引生成器类"""
    
    def __init__(self, rules_dir: Union[str, Path] = "rules", index_dir: Union[str, Path] = "index"):
        """
        初始化索引生成器
        
        Args:
            rules_dir: 规则目录
            index_dir: 索引目录
        """
        self.rules_dir = Path(rules_dir)
        self.index_dir = Path(index_dir)
        ensure_dir(self.index_dir)
        
        # 索引文件路径
        self.main_index_path = self.index_dir / "rules_index.json"
        self.compact_index_path = self.index_dir / "rules_index_compact.json"
        self.source_indices = {}  # 每个源的索引
        
        # 索引版本
        self.version = "1.0.0"
    
    def generate_index(self) -> Dict:
        """
        生成规则索引
        
        Returns:
            Dict: 索引生成统计信息
        """
        logger.info("开始生成规则索引")
        
        start_time = datetime.now()
        
        # 创建索引元数据
        index = {
            "meta": {
                "version": self.version,
                "generated_at": start_time.isoformat(),
                "total_rules": 0,
                "sources": {}
            },
            "rules": []
        }
        
        # 统计信息
        stats = {
            "total_sources": 0,
            "total_rules": 0,
            "source_stats": {},
            "start_time": start_time.isoformat(),
            "end_time": None,
            "success": False
        }
        
        try:
            # 获取所有规则源目录
            source_dirs = [d for d in self.rules_dir.iterdir() if d.is_dir()]
            stats["total_sources"] = len(source_dirs)
            
            # 处理每个规则源
            for source_dir in source_dirs:
                source_name = source_dir.name
                logger.info(f"处理规则源: {source_name}")
                
                # 初始化源统计
                source_stats = {
                    "name": source_name,
                    "rules_count": 0
                }
                
                # 获取所有规则文件
                rule_files = list_files(source_dir, "*.json")
                
                # 创建源索引
                source_index = {
                    "meta": {
                        "source": source_name,
                        "version": self.version,
                        "generated_at": start_time.isoformat(),
                        "total_rules": len(rule_files)
                    },
                    "rules": []
                }
                
                # 处理每个规则文件
                for rule_file in rule_files:
                    try:
                        # 读取规则文件
                        rule = read_json(rule_file)
                        
                        # 创建索引条目
                        rule_entry = self._create_rule_entry(rule, rule_file)
                        
                        # 添加到主索引和源索引
                        index["rules"].append(rule_entry)
                        source_index["rules"].append(rule_entry)
                        
                        # 更新统计信息
                        source_stats["rules_count"] += 1
                        stats["total_rules"] += 1
                        
                    except Exception as e:
                        logger.error(f"处理规则文件 {rule_file} 时发生错误: {e}")
                
                # 更新源元数据
                source_index["meta"]["total_rules"] = source_stats["rules_count"]
                
                # 保存源索引
                source_index_path = self.index_dir / f"{source_name}_index.json"
                write_json(source_index, source_index_path)
                self.source_indices[source_name] = source_index_path
                
                # 更新主索引源信息
                index["meta"]["sources"][source_name] = {
                    "count": source_stats["rules_count"],
                    "index_path": str(source_index_path.relative_to(self.index_dir))
                }
                
                # 更新统计信息
                stats["source_stats"][source_name] = source_stats
            
            # 更新总规则数
            index["meta"]["total_rules"] = stats["total_rules"]
            
            # 验证索引格式
            self._validate_index(index)
            
            # 保存主索引
            write_json(index, self.main_index_path)
            logger.info(f"主索引已保存到: {self.main_index_path}")
            
            # 生成精简索引
            compact_index = self._generate_compact_index(index)
            write_json(compact_index, self.compact_index_path)
            logger.info(f"精简索引已保存到: {self.compact_index_path}")
            
            # 生成标签索引
            self._generate_tag_index(index)
            
            # 生成MITRE索引
            self._generate_mitre_index(index)
            
            # 更新统计信息
            end_time = datetime.now()
            stats["end_time"] = end_time.isoformat()
            stats["duration"] = (end_time - start_time).total_seconds()
            stats["success"] = True
            
            logger.info(f"规则索引生成完成，共 {stats['total_rules']} 条规则，{stats['total_sources']} 个规则源")
            
        except Exception as e:
            logger.error(f"生成规则索引时发生错误: {e}")
            # 更新统计信息
            end_time = datetime.now()
            stats["end_time"] = end_time.isoformat()
            stats["duration"] = (end_time - start_time).total_seconds()
            stats["error"] = str(e)
            stats["success"] = False
        
        # 保存统计信息
        stats_path = self.index_dir / "index_stats.json"
        write_json(stats, stats_path)
        
        return stats
    
    def _create_rule_entry(self, rule: Dict, rule_file: Path) -> Dict:
        """
        创建规则索引条目
        
        Args:
            rule: 规则内容
            rule_file: 规则文件路径
            
        Returns:
            Dict: 规则索引条目
        """
        # 基本信息
        entry = {
            "id": rule.get("id", ""),
            "name": rule.get("name", ""),
            "description": rule.get("description", ""),
            "source": {
                "type": rule.get("source", {}).get("type", "unknown"),
                "id": rule.get("source", {}).get("id", "")
            },
            "severity": rule.get("severity", "medium"),
            "tags": rule.get("tags", []),
            "platforms": rule.get("platforms", []),
            "mitre": {
                "tactics": rule.get("mitre", {}).get("tactics", []),
                "techniques": rule.get("mitre", {}).get("techniques", [])
            },
            "created": rule.get("created", ""),
            "modified": rule.get("modified", ""),
            "rule_path": str(rule_file.relative_to(self.rules_dir.parent))
        }
        
        return entry
    
    def _validate_index(self, index: Dict) -> None:
        """
        验证索引是否符合模式
        
        Args:
            index: 索引数据
            
        Raises:
            jsonschema.exceptions.ValidationError: 验证失败
        """
        try:
            jsonschema.validate(instance=index, schema=INDEX_SCHEMA)
            logger.info("索引验证通过")
        except jsonschema.exceptions.ValidationError as e:
            logger.error(f"索引验证失败: {e}")
            raise
    
    def _generate_compact_index(self, index: Dict) -> Dict:
        """
        生成精简索引
        仅包含ID、名称、严重程度和规则路径
        
        Args:
            index: 完整索引
            
        Returns:
            Dict: 精简索引
        """
        compact_index = {
            "meta": index["meta"].copy(),
            "rules": []
        }
        
        for rule in index["rules"]:
            compact_rule = {
                "id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "rule_path": rule["rule_path"]
            }
            compact_index["rules"].append(compact_rule)
        
        return compact_index
    
    def _generate_tag_index(self, index: Dict) -> None:
        """
        生成标签索引
        
        Args:
            index: 完整索引
        """
        # 收集所有标签
        tags_dict = {}
        
        for rule in index["rules"]:
            for tag in rule.get("tags", []):
                if tag not in tags_dict:
                    tags_dict[tag] = []
                
                # 添加规则ID到标签索引
                tags_dict[tag].append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "rule_path": rule["rule_path"]
                })
        
        # 生成标签索引
        tag_index = {
            "meta": {
                "version": self.version,
                "generated_at": index["meta"]["generated_at"],
                "total_tags": len(tags_dict)
            },
            "tags": {}
        }
        
        # 添加标签
        for tag, rules in tags_dict.items():
            tag_index["tags"][tag] = {
                "count": len(rules),
                "rules": rules
            }
        
        # 保存标签索引
        tag_index_path = self.index_dir / "tags_index.json"
        write_json(tag_index, tag_index_path)
        logger.info(f"标签索引已保存到: {tag_index_path}")
    
    def _generate_mitre_index(self, index: Dict) -> None:
        """
        生成MITRE索引
        
        Args:
            index: 完整索引
        """
        # 收集所有战术和技术
        tactics_dict = {}
        techniques_dict = {}
        
        for rule in index["rules"]:
            mitre = rule.get("mitre", {})
            
            # 处理战术
            for tactic in mitre.get("tactics", []):
                if tactic not in tactics_dict:
                    tactics_dict[tactic] = []
                
                # 添加规则ID到战术索引
                tactics_dict[tactic].append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "rule_path": rule["rule_path"]
                })
            
            # 处理技术
            for technique in mitre.get("techniques", []):
                if technique not in techniques_dict:
                    techniques_dict[technique] = []
                
                # 添加规则ID到技术索引
                techniques_dict[technique].append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "rule_path": rule["rule_path"]
                })
        
        # 生成MITRE索引
        mitre_index = {
            "meta": {
                "version": self.version,
                "generated_at": index["meta"]["generated_at"],
                "total_tactics": len(tactics_dict),
                "total_techniques": len(techniques_dict)
            },
            "tactics": {},
            "techniques": {}
        }
        
        # 添加战术
        for tactic, rules in tactics_dict.items():
            mitre_index["tactics"][tactic] = {
                "count": len(rules),
                "rules": rules
            }
        
        # 添加技术
        for technique, rules in techniques_dict.items():
            mitre_index["techniques"][technique] = {
                "count": len(rules),
                "rules": rules
            }
        
        # 保存MITRE索引
        mitre_index_path = self.index_dir / "mitre_index.json"
        write_json(mitre_index, mitre_index_path)
        logger.info(f"MITRE索引已保存到: {mitre_index_path}")
    
    def search_rules(self, query: Dict) -> List[Dict]:
        """
        搜索规则
        
        Args:
            query: 搜索条件
            
        Returns:
            List[Dict]: 匹配的规则列表
        """
        # 从索引加载规则
        try:
            index = read_json(self.main_index_path)
            rules = index["rules"]
        except Exception as e:
            logger.error(f"加载索引失败: {e}")
            return []
        
        # 过滤规则
        matched_rules = []
        
        for rule in rules:
            # 初始匹配为True，如果任一条件不满足则设为False
            match = True
            
            # 匹配ID
            if "id" in query and query["id"] != rule["id"]:
                match = False
                continue
            
            # 匹配名称
            if "name" in query and query["name"].lower() not in rule["name"].lower():
                match = False
                continue
            
            # 匹配描述
            if "description" in query and query["description"].lower() not in rule.get("description", "").lower():
                match = False
                continue
            
            # 匹配标签
            if "tags" in query:
                if not all(tag in rule.get("tags", []) for tag in query["tags"]):
                    match = False
                    continue
            
            # 匹配严重程度
            if "severity" in query and query["severity"] != rule["severity"]:
                match = False
                continue
            
            # 匹配平台
            if "platforms" in query:
                if not all(platform in rule.get("platforms", []) for platform in query["platforms"]):
                    match = False
                    continue
            
            # 匹配MITRE战术
            if "mitre_tactics" in query:
                mitre_tactics = rule.get("mitre", {}).get("tactics", [])
                if not all(tactic in mitre_tactics for tactic in query["mitre_tactics"]):
                    match = False
                    continue
            
            # 匹配MITRE技术
            if "mitre_techniques" in query:
                mitre_techniques = rule.get("mitre", {}).get("techniques", [])
                if not all(technique in mitre_techniques for technique in query["mitre_techniques"]):
                    match = False
                    continue
            
            # 匹配源类型
            if "source_type" in query and query["source_type"] != rule["source"]["type"]:
                match = False
                continue
            
            # 如果所有条件都匹配，添加到结果
            if match:
                matched_rules.append(rule)
        
        return matched_rules


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="规则索引生成器")
    parser.add_argument("--rules-dir", default="rules", help="规则目录")
    parser.add_argument("--index-dir", default="index", help="索引目录")
    args = parser.parse_args()
    
    # 设置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建索引生成器
    indexer = RuleIndexer(args.rules_dir, args.index_dir)
    
    # 生成索引
    stats = indexer.generate_index()
    
    if stats["success"]:
        logger.info(f"索引生成成功，共 {stats['total_rules']} 条规则")
    else:
        logger.error(f"索引生成失败: {stats.get('error', '未知错误')}")


if __name__ == "__main__":
    main()