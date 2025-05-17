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
from typing import Dict, List, Any, Optional, Union
import jsonschema

from ..utils.file_utils import (
    ensure_dir, read_json, write_json, 
    list_files, get_file_hash
)

import collections

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
                    "platforms": {
                        "type": "array",
                        "items": {"type": "string"}
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
        self.rules_dir = Path(rules_dir)
        self.index_dir = Path(index_dir)
        ensure_dir(self.index_dir)
        self.main_index_path = self.index_dir / "rules_index.json"
        self.compact_index_path = self.index_dir / "rules_index_compact.json"
        self.source_indices = {}
        self.version = "1.0.0"

    def generate_indexes(self):
        metadata_files = list(self._find_metadata_files())
        all_rules = self._load_all_rules(metadata_files)

        # 生成主索引
        main_index = self._generate_main_index(all_rules)
        write_json(self.index_dir / "main_index.json", main_index)

        # 生成源索引
        source_index = self._generate_source_index(all_rules)
        write_json(self.index_dir / "source_index.json", source_index)

        # 生成精简索引
        compact_index = self._generate_compact_index(all_rules)
        write_json(self.index_dir / "compact_index.json", compact_index)

        # 生成统计信息
        stats = self._generate_stats(all_rules)
        write_json(self.index_dir / "stats.json", stats)

    def _find_metadata_files(self):
        for root, dirs, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith("_metadata.json"):
                    yield Path(root) / file

    def _load_all_rules(self, metadata_files):
        all_rules = []
        for file in metadata_files:
            try:
                rules = read_json(file)
                for rule in rules:
                    if 'tags' in rule and not isinstance(rule['tags'], list):
                        # 处理非列表类型的 tags（转换为字符串数组）
                        new_tags = []
                        if isinstance(rule['tags'], dict):
                            # 将字典键值对转换为"key:value"格式的字符串
                            for key, values in rule['tags'].items():
                                if isinstance(values, list):
                                    for value in values:
                                        new_tags.append(f"{key}:{value}")
                                else:
                                    new_tags.append(f"{key}:{values}")
                        else:
                            # 其他类型直接转为字符串
                            new_tags.append(str(rule['tags']))
                        rule['tags'] = new_tags
                all_rules.extend(rules)
            except Exception as e:
                logger.error(f"Failed to load {file}: {e}")
        return all_rules

    def _generate_main_index(self, rules):
        main_index = {
            "meta": {
                "version": "1.0",
                "generated_at": datetime.utcnow().isoformat(),
                "total_rules": len(rules)
            },
            "rules": rules
        }
        return main_index

    def _generate_source_index(self, rules):
        source_index = collections.defaultdict(list)
        for rule in rules:
            if "source" in rule:
                source_type = rule["source"].get("type", "unknown")
                source_index[source_type].append(rule["id"])
        return dict(source_index)

    def _generate_compact_index(self, rules):
        compact_index = []
        for rule in rules:
            compact_rule = {
                "id": rule["id"],
                "name": rule["name"],
                "tags": rule.get("tags", []),
                "severity": rule.get("severity", "unknown")
            }
            compact_index.append(compact_rule)
        return compact_index

    def _generate_stats(self, rules):
        stats = {
            "total_rules": len(rules),
            "by_source": collections.Counter(rule["source"].get("type", "unknown") for rule in rules if "source" in rule),
            "by_severity": collections.Counter(rule.get("severity", "unknown") for rule in rules),
            "by_status": collections.Counter(rule.get("status", "unknown") for rule in rules)
        }
        return stats

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

        metadata_files = [
            Path('rules/sigma/sigma_metadata.json'),
            Path('rules/splunk/splunk_metadata.json'),
            Path('rules/elastic/elastic_metadata.json')
        ]

        stats["total_sources"] = len(metadata_files)

        for metadata_file in metadata_files:
            source_name = metadata_file.parent.name
            logger.info(f"处理规则源: {source_name}")

            # 初始化源统计
            source_stats = {
                "name": source_name,
                "rules_count": 0
            }

            try:
                rules = read_json(metadata_file)
                source_index = {
                    "meta": {
                        "source": source_name,
                        "version": self.version,
                        "generated_at": start_time.isoformat(),
                        "total_rules": len(rules)
                    },
                    "rules": []
                }

                for rule in rules:
                    try:
                        rule_entry = self._create_rule_entry(rule, metadata_file)
                        rule_entry["source"] = {"type": source_name}

                        # 添加到主索引和源索引
                        index["rules"].append(rule_entry)
                        source_index["rules"].append(rule_entry)

                        # 更新统计信息
                        source_stats["rules_count"] += 1
                        stats["total_rules"] += 1

                    except Exception as e:
                        logger.error(f"处理规则 {rule.get('id')} 时发生错误: {e}")

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

            except Exception as e:
                logger.error(f"处理元数据文件 {metadata_file} 时发生错误: {e}")

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
        # 更新统计信息
        end_time = datetime.now()
        stats["end_time"] = end_time.isoformat()
        stats["duration"] = (end_time - start_time).total_seconds()
        stats["success"] = True

        logger.info(f"规则索引生成完成，共 {stats['total_rules']} 条规则，{stats['total_sources']} 个规则源")

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
            "source": rule.get("source", {}),
            "severity": rule.get("severity", "medium"),
            "tags": rule.get("tags", []),
            "platforms": rule.get("platforms", []),
            "created": rule.get("created", ""),
            "modified": rule.get("modified", ""),
            "rule_path": str(rule_file.relative_to(self.rules_dir))
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