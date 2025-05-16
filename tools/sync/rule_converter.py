#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则转换器模块
负责将不同格式的规则转换为标准格式
"""

import os
import json
import yaml
import logging
import re
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, date
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set

from ..utils.file_utils import (
    read_yaml, read_json, write_json, 
    list_files, read_ndjson
)

logger = logging.getLogger(__name__)

class RuleConverter(ABC):
    """规则转换器抽象基类"""
    
    def __init__(self):
        self.source_type = self.__class__.__name__.replace("Converter", "").lower()
    
    @abstractmethod
    def convert(self, rule_content: Dict, file_path: str) -> Dict:
        """
        将规则转换为标准格式
        
        Args:
            rule_content: 原始规则内容
            file_path: 规则文件路径
            
        Returns:
            Dict: 标准格式的规则
        """
        pass
    
    def generate_rule_id(self, prefix: str = None) -> str:
        """
        生成规则ID
        
        Args:
            prefix: ID前缀
            
        Returns:
            str: 规则ID
        """
        unique_id = str(uuid.uuid4())
        if prefix:
            return f"{prefix}-{unique_id}"
        return unique_id
    
    def normalize_tags(self, tags: List[str]) -> List[str]:
        """
        标准化标签
        
        Args:
            tags: 原始标签列表
            
        Returns:
            List[str]: 标准化后的标签列表
        """
        if not tags:
            return []
            
        # 转换为小写，去除特殊字符
        normalized = []
        for tag in tags:
            if not tag or not isinstance(tag, str):
                continue
                
            # 转换为小写，替换空格为下划线，去除特殊字符
            normalized_tag = re.sub(r'[^\w\-]', '', tag.lower().replace(' ', '_'))
            if normalized_tag:
                normalized.append(normalized_tag)
                
        # 去重
        return sorted(list(set(normalized)))
    
    def extract_mitre_tactics(self, rule_content: Dict) -> List[str]:
        """
        从规则中提取MITRE ATT&CK战术
        根据不同规则格式，重写此方法
        
        Args:
            rule_content: 规则内容
            
        Returns:
            List[str]: MITRE战术列表
        """
        return []
    
    def extract_mitre_techniques(self, rule_content: Dict) -> List[str]:
        """
        从规则中提取MITRE ATT&CK技术
        根据不同规则格式，重写此方法
        
        Args:
            rule_content: 规则内容
            
        Returns:
            List[str]: MITRE技术列表
        """
        return []
    
    def standardize_severity(self, severity: str) -> str:
        """
        标准化严重程度
        
        Args:
            severity: 原始严重程度
            
        Returns:
            str: 标准化的严重程度 (low, medium, high, critical)
        """
        severity = str(severity).lower().strip()
        
        if severity in ('low', 'l', 'info', 'informational'):
            return 'low'
        elif severity in ('medium', 'm', 'med', 'moderate'):
            return 'medium'
        elif severity in ('high', 'h', 'important'):
            return 'high'
        elif severity in ('critical', 'c', 'crit', 'severe'):
            return 'critical'
        else:
            return 'medium'  # 默认为medium
    
    def format_date_for_json(self, date_obj: Any) -> str:
        """
        将日期对象转换为JSON可序列化的字符串格式
        
        Args:
            date_obj: 日期对象或字符串
            
        Returns:
            str: 日期字符串
        """
        if isinstance(date_obj, (datetime, date)):
            return date_obj.isoformat()
        elif date_obj:
            return str(date_obj)
        return ""
    
    def get_standard_rule_template(self) -> Dict:
        """
        获取标准规则模板
        
        Returns:
            Dict: 标准规则模板
        """
        return {
            "id": "",                      # 规则唯一ID
            "name": "",                    # 规则名称
            "description": "",             # 规则描述
            "source": {
                "type": self.source_type,  # 规则源类型
                "id": "",                  # 原始规则ID
                "url": "",                 # 原始规则URL
                "file_path": ""            # 原始规则文件路径
            },
            "tags": [],                    # 标签列表
            "author": "",                  # 作者
            "references": [],              # 参考链接
            "severity": "medium",          # 严重程度
            "type": "",                    # 规则类型
            "status": "experimental",      # 规则状态
            "created": "",                 # 创建时间
            "modified": "",                # 修改时间
            "mitre": {
                "tactics": [],             # MITRE战术
                "techniques": []           # MITRE技术
            },
            "detection": {
                "query": "",               # 检测查询
                "condition": "",           # 检测条件
                "fields": []               # 相关字段
            },
            "falsepositives": [],          # 误报情况
            "level": "medium",             # 风险等级
            "rule_format": "standard",     # 规则格式
            "platforms": [],               # 适用平台
            "data_sources": []             # 数据源
        }


class SigmaConverter(RuleConverter):
    """Sigma规则转换器"""
    
    def convert(self, rule_content: Dict, file_path: str) -> Dict:
        """
        将Sigma规则转换为标准格式
        
        Args:
            rule_content: Sigma规则内容
            file_path: 规则文件路径
            
        Returns:
            Dict: 标准格式的规则
        """
        # 获取标准规则模板
        standard_rule = self.get_standard_rule_template()
        
        # 提取基本信息
        standard_rule["id"] = rule_content.get("id", self.generate_rule_id("sigma"))
        standard_rule["name"] = rule_content.get("title", "")
        standard_rule["description"] = rule_content.get("description", "")
        
        # 源信息
        standard_rule["source"]["id"] = rule_content.get("id", "")
        standard_rule["source"]["file_path"] = file_path
        
        # 获取相对路径作为URL的一部分
        relative_path = os.path.basename(file_path)
        standard_rule["source"]["url"] = f"https://github.com/SigmaHQ/sigma/blob/master/{relative_path}"
        
        # 提取和标准化标签
        sigma_tags = rule_content.get("tags", []) or []
        # 添加特殊处理，从标签中提取常见平台信息
        platforms = self._extract_platforms_from_tags(sigma_tags)
        standard_rule["platforms"] = platforms
        
        standard_rule["tags"] = self.normalize_tags(sigma_tags)
        standard_rule["author"] = rule_content.get("author", "")
        standard_rule["references"] = rule_content.get("references", []) or []
        
        # 标准化严重程度
        level = rule_content.get("level", "medium")
        standard_rule["severity"] = self.standardize_severity(level)
        standard_rule["level"] = standard_rule["severity"]  # 保持一致
        
        # 规则类型
        standard_rule["type"] = "sigma"
        standard_rule["status"] = rule_content.get("status", "experimental")
        
        # 日期处理
        created_date = rule_content.get("date", "")
        modified_date = rule_content.get("modified", "")
        
        standard_rule["created"] = self.format_date_for_json(created_date)
        standard_rule["modified"] = self.format_date_for_json(modified_date) if modified_date else self.format_date_for_json(created_date)
        
        # MITRE映射
        mitre_attack = rule_content.get("tags", [])
        standard_rule["mitre"]["tactics"] = self._extract_mitre_tactics(mitre_attack)
        standard_rule["mitre"]["techniques"] = self._extract_mitre_techniques(mitre_attack)
        
        # 检测部分
        detection = rule_content.get("detection", {})
        condition = detection.get("condition", "")
        
        # 合并所有检测定义为查询字符串
        query_parts = []
        for key, value in detection.items():
            if key != "condition" and value:
                query_parts.append(f"{key}: {json.dumps(value)}")
        
        standard_rule["detection"]["query"] = "\n".join(query_parts)
        standard_rule["detection"]["condition"] = condition
        
        # 可能的字段
        fields = rule_content.get("fields", []) or []
        standard_rule["detection"]["fields"] = fields
        
        # 误报信息
        standard_rule["falsepositives"] = rule_content.get("falsepositives", []) or []
        
        # 可能的数据源
        logsource = rule_content.get("logsource", {})
        data_sources = []
        for key in ["product", "service", "category"]:
            if key in logsource and logsource[key]:
                data_sources.append(logsource[key])
        
        standard_rule["data_sources"] = data_sources
        
        return standard_rule
    
    def _extract_platforms_from_tags(self, tags: List[str]) -> List[str]:
        """
        从标签中提取平台信息
        
        Args:
            tags: 标签列表
            
        Returns:
            List[str]: 平台列表
        """
        platforms = set()
        platform_keywords = {
            "windows": "windows",
            "linux": "linux",
            "macos": "macos",
            "mac": "macos",
            "azure": "azure",
            "aws": "aws",
            "gcp": "gcp",
            "google-cloud": "gcp",
            "cloud": "cloud",
            "container": "container",
            "kubernetes": "kubernetes",
            "k8s": "kubernetes",
            "docker": "container"
        }
        
        for tag in tags:
            tag_lower = tag.lower()
            for keyword, platform in platform_keywords.items():
                if keyword in tag_lower:
                    platforms.add(platform)
        
        return sorted(list(platforms))
    
    def _extract_mitre_tactics(self, tags: List[str]) -> List[str]:
        """
        从Sigma标签中提取MITRE战术
        
        Args:
            tags: 标签列表
            
        Returns:
            List[str]: MITRE战术列表
        """
        tactics = []
        for tag in tags:
            if not isinstance(tag, str):
                continue
                
            # Sigma使用如 attack.tXXXX 的格式表示战术
            match = re.match(r'attack\.t(\d+)', tag.lower())
            if match:
                tactic_id = f"TA{match.group(1)}"
                tactics.append(tactic_id)
        
        return sorted(list(set(tactics)))
    
    def _extract_mitre_techniques(self, tags: List[str]) -> List[str]:
        """
        从Sigma标签中提取MITRE技术
        
        Args:
            tags: 标签列表
            
        Returns:
            List[str]: MITRE技术列表
        """
        techniques = []
        for tag in tags:
            if not isinstance(tag, str):
                continue
                
            # Sigma使用如 attack.tXXXX.YYY 的格式表示技术
            match = re.match(r'attack\.t\d+\.(\d+)', tag.lower())
            if match:
                technique_id = f"T{match.group(1)}"
                techniques.append(technique_id)
        
        return sorted(list(set(techniques)))


class ElasticConverter(RuleConverter):
    """Elastic规则转换器"""
    
    def convert(self, rule_content: Dict, file_path: str) -> Dict:
        """
        将Elastic规则转换为标准格式
        
        Args:
            rule_content: Elastic规则内容
            file_path: 规则文件路径
            
        Returns:
            Dict: 标准格式的规则
        """
        # 获取标准规则模板
        standard_rule = self.get_standard_rule_template()
        
        # 提取基本信息
        standard_rule["id"] = rule_content.get("rule_id", self.generate_rule_id("elastic"))
        standard_rule["name"] = rule_content.get("name", "")
        standard_rule["description"] = rule_content.get("description", "")
        
        # 源信息
        standard_rule["source"]["id"] = rule_content.get("rule_id", "")
        standard_rule["source"]["file_path"] = file_path
        
        # 获取相对路径作为URL的一部分
        relative_path = os.path.basename(file_path)
        standard_rule["source"]["url"] = f"https://github.com/elastic/detection-rules/blob/main/{relative_path}"
        
        # 标签处理
        elastic_tags = rule_content.get("tags", []) or []
        standard_rule["tags"] = self.normalize_tags(elastic_tags)
        
        # 作者信息
        author = rule_content.get("author", [])
        if isinstance(author, list):
            standard_rule["author"] = ", ".join(author)
        else:
            standard_rule["author"] = str(author)
        
        # 引用链接
        standard_rule["references"] = rule_content.get("references", []) or []
        
        # 标准化严重程度
        severity = rule_content.get("severity", "medium")
        standard_rule["severity"] = self.standardize_severity(severity)
        standard_rule["level"] = standard_rule["severity"]
        
        # 规则类型
        standard_rule["type"] = rule_content.get("type", "query")
        standard_rule["status"] = "production"  # Elastic规则通常是生产就绪的
        
        # 日期处理
        # Elastic规则时间格式可能是RFC3339
        created_date = rule_content.get("created_at", "")
        modified_date = rule_content.get("updated_at", "")
        
        standard_rule["created"] = self.format_date_for_json(created_date)
        standard_rule["modified"] = self.format_date_for_json(modified_date) if modified_date else self.format_date_for_json(created_date)
        
        # 平台信息
        os_list = rule_content.get("os_types", [])
        if os_list:
            standard_rule["platforms"] = os_list
        
        # MITRE映射
        threat = rule_content.get("threat", []) or []
        standard_rule["mitre"]["tactics"] = self._extract_mitre_tactics(threat)
        standard_rule["mitre"]["techniques"] = self._extract_mitre_techniques(threat)
        
        # 检测部分
        query = rule_content.get("query", "")
        language = rule_content.get("language", "")
        
        standard_rule["detection"]["query"] = query
        standard_rule["detection"]["condition"] = f"Language: {language}"
        
        # 相关字段
        fields = []
        index_fields = rule_content.get("related_integrations", [])
        for field in index_fields:
            if isinstance(field, str):
                fields.append(field)
            elif isinstance(field, dict) and "fields" in field:
                fields.extend(field["fields"])
        
        standard_rule["detection"]["fields"] = sorted(list(set(fields)))
        
        # 误报信息
        false_positives = rule_content.get("false_positives", []) or []
        standard_rule["falsepositives"] = false_positives
        
        # 数据源
        data_sources = []
        # 从风险得分映射和索引模式提取可能的数据源
        risk_score_mapping = rule_content.get("risk_score_mapping", [])
        if risk_score_mapping:
            for mapping in risk_score_mapping:
                if "field" in mapping:
                    data_sources.append(mapping["field"])
        
        index = rule_content.get("index", [])
        if index and isinstance(index, list):
            data_sources.extend(index)
        
        standard_rule["data_sources"] = sorted(list(set(data_sources)))
        
        return standard_rule
    
    def _extract_mitre_tactics(self, threat: List[Dict]) -> List[str]:
        """
        从Elastic威胁数据中提取MITRE战术
        
        Args:
            threat: 威胁列表
            
        Returns:
            List[str]: MITRE战术列表
        """
        tactics = []
        for item in threat:
            if isinstance(item, dict) and "tactic" in item:
                tactic = item.get("tactic", {})
                tactic_id = tactic.get("id", "")
                if tactic_id:
                    tactics.append(tactic_id)
        
        return sorted(list(set(tactics)))
    
    def _extract_mitre_techniques(self, threat: List[Dict]) -> List[str]:
        """
        从Elastic威胁数据中提取MITRE技术
        
        Args:
            threat: 威胁列表
            
        Returns:
            List[str]: MITRE技术列表
        """
        techniques = []
        for item in threat:
            if isinstance(item, dict) and "technique" in item:
                technique = item.get("technique", [])
                if isinstance(technique, list):
                    for t in technique:
                        technique_id = t.get("id", "")
                        if technique_id:
                            techniques.append(technique_id)
                elif isinstance(technique, dict):
                    technique_id = technique.get("id", "")
                    if technique_id:
                        techniques.append(technique_id)
        
        return sorted(list(set(techniques)))


class SplunkConverter(RuleConverter):
    """Splunk规则转换器"""
    
    def convert(self, rule_content: Dict, file_path: str) -> Dict:
        """
        将Splunk规则转换为标准格式
        
        Args:
            rule_content: Splunk规则内容
            file_path: 规则文件路径
            
        Returns:
            Dict: 标准格式的规则
        """
        # 获取标准规则模板
        standard_rule = self.get_standard_rule_template()
        
        # 提取基本信息
        standard_rule["id"] = rule_content.get("id", self.generate_rule_id("splunk"))
        standard_rule["name"] = rule_content.get("name", "")
        standard_rule["description"] = rule_content.get("description", "")
        
        # 源信息
        standard_rule["source"]["id"] = rule_content.get("id", "")
        standard_rule["source"]["file_path"] = file_path
        
        # 获取相对路径作为URL的一部分
        relative_path = os.path.basename(file_path)
        standard_rule["source"]["url"] = f"https://github.com/splunk/security_content/blob/develop/{relative_path}"
        
        # 标签处理
        tags = []
        if "tags" in rule_content:
            tags.extend(rule_content["tags"])
        if "analytic_types" in rule_content:
            tags.extend(rule_content["analytic_types"])
            
        standard_rule["tags"] = self.normalize_tags(tags)
        
        # 作者信息
        standard_rule["author"] = rule_content.get("author", "")
        
        # 引用链接
        standard_rule["references"] = rule_content.get("references", []) or []
        
        # 标准化严重程度
        severity = rule_content.get("risk_score_mapping", {}).get("default_severity", "medium")
        standard_rule["severity"] = self.standardize_severity(severity)
        standard_rule["level"] = standard_rule["severity"]
        
        # 规则类型
        standard_rule["type"] = "splunk"
        status = "experimental"
        if rule_content.get("status", "") == "production":
            status = "production"
        standard_rule["status"] = status
        
        # 日期处理
        created_date = rule_content.get("date", "")
        modified_date = rule_content.get("modified", "")
        
        standard_rule["created"] = self.format_date_for_json(created_date)
        standard_rule["modified"] = self.format_date_for_json(modified_date) if modified_date else self.format_date_for_json(created_date)
        
        # 平台信息
        supported_platforms = rule_content.get("supported_platforms", [])
        standard_rule["platforms"] = supported_platforms
        
        # MITRE映射
        mitre_attack = rule_content.get("mitre_attack_id", []) or []
        for attack_id in mitre_attack:
            if attack_id.startswith("T"):
                standard_rule["mitre"]["techniques"].append(attack_id)
            elif attack_id.startswith("TA"):
                standard_rule["mitre"]["tactics"].append(attack_id)
        
        # 检测部分
        search = rule_content.get("search", "")
        standard_rule["detection"]["query"] = search
        standard_rule["detection"]["condition"] = rule_content.get("how_to_implement", "")
        
        # 相关字段
        fields = rule_content.get("fields", []) or []
        standard_rule["detection"]["fields"] = fields
        
        # 误报信息
        false_positives = rule_content.get("known_false_positives", "")
        if false_positives:
            standard_rule["falsepositives"] = [false_positives]
        
        # 数据源
        data_model_mapping = rule_content.get("data_model_mapping", {})
        data_sources = []
        for mapping in data_model_mapping.values():
            if isinstance(mapping, dict) and "fields" in mapping:
                data_sources.extend(mapping["fields"])
            
        standard_rule["data_sources"] = sorted(list(set(data_sources)))
        
        return standard_rule


class MitreConverter(RuleConverter):
    """MITRE规则转换器"""
    
    def convert(self, rule_content: Dict, file_path: str) -> Dict:
        """
        将MITRE规则转换为标准格式
        
        Args:
            rule_content: MITRE规则内容
            file_path: 规则文件路径
            
        Returns:
            Dict: 标准格式的规则
        """
        # 获取标准规则模板
        standard_rule = self.get_standard_rule_template()
        
        # 提取基本信息
        standard_rule["id"] = rule_content.get("id", self.generate_rule_id("mitre"))
        standard_rule["name"] = rule_content.get("name", "")
        standard_rule["description"] = rule_content.get("description", "")
        
        # 源信息
        standard_rule["source"]["id"] = rule_content.get("id", "")
        standard_rule["source"]["file_path"] = file_path
        
        # 获取相对路径作为URL的一部分
        relative_path = os.path.basename(file_path)
        standard_rule["source"]["url"] = f"https://github.com/mitre/detection-lab-rules/blob/main/{relative_path}"
        
        # 标签处理
        tags = rule_content.get("tags", []) or []
        standard_rule["tags"] = self.normalize_tags(tags)
        standard_rule["tags"].append("mitre")
        
        # 作者信息
        standard_rule["author"] = rule_content.get("author", "MITRE")
        
        # 引用链接
        standard_rule["references"] = rule_content.get("references", []) or []
        
        # 标准化严重程度
        severity = rule_content.get("severity", "medium")
        standard_rule["severity"] = self.standardize_severity(severity)
        standard_rule["level"] = standard_rule["severity"]
        
        # 规则类型
        standard_rule["type"] = "mitre"
        standard_rule["status"] = rule_content.get("status", "experimental")
        
        # 日期处理
        created_date = rule_content.get("created", "")
        modified_date = rule_content.get("last_modified", "")
        
        standard_rule["created"] = self.format_date_for_json(created_date)
        standard_rule["modified"] = self.format_date_for_json(modified_date) if modified_date else self.format_date_for_json(created_date)
        
        # 平台信息
        platforms = rule_content.get("platforms", [])
        standard_rule["platforms"] = platforms
        
        # MITRE映射
        attack_mappings = rule_content.get("attack_mappings", []) or []
        
        for mapping in attack_mappings:
            if isinstance(mapping, dict):
                tactic = mapping.get("tactic", "")
                technique = mapping.get("technique", "")
                
                if tactic and tactic.startswith("TA"):
                    standard_rule["mitre"]["tactics"].append(tactic)
                
                if technique and technique.startswith("T"):
                    standard_rule["mitre"]["techniques"].append(technique)
        
        # 检测部分
        detection = rule_content.get("detection", {})
        query = detection.get("query", "")
        condition = detection.get("condition", "")
        
        standard_rule["detection"]["query"] = query
        standard_rule["detection"]["condition"] = condition
        
        # 相关字段
        fields = detection.get("fields", []) or []
        standard_rule["detection"]["fields"] = fields
        
        # 误报信息
        false_positives = rule_content.get("false_positives", []) or []
        standard_rule["falsepositives"] = false_positives
        
        # 数据源
        data_sources = rule_content.get("data_sources", []) or []
        standard_rule["data_sources"] = data_sources
        
        return standard_rule


class ConverterFactory:
    """转换器工厂类"""
    
    @staticmethod
    def get_converter(source_type: str) -> RuleConverter:
        """
        根据类型获取相应的转换器
        
        Args:
            source_type: 规则源类型
            
        Returns:
            RuleConverter: 对应的转换器实例
            
        Raises:
            ValueError: 不支持的规则源类型
        """
        converters = {
            "sigma": SigmaConverter,
            "sigma_converter": SigmaConverter,
            "elastic": ElasticConverter,
            "elastic_converter": ElasticConverter,
            "splunk": SplunkConverter,
            "splunk_converter": SplunkConverter,
            "mitre": MitreConverter,
            "mitre_converter": MitreConverter
        }
        
        converter_class = converters.get(source_type.lower())
        if not converter_class:
            raise ValueError(f"不支持的规则源类型: {source_type}")
            
        return converter_class()
    
    @staticmethod
    def load_and_convert_rule(file_path: Union[str, Path], converter_type: str) -> Optional[Dict]:
        """
        加载并转换规则文件
        
        Args:
            file_path: 规则文件路径
            converter_type: 转换器类型
            
        Returns:
            Optional[Dict]: 转换后的规则，失败则返回None
        """
        file_path = Path(file_path)
        if not file_path.exists():
            logger.error(f"规则文件不存在: {file_path}")
            return None
        
        try:
            # 根据文件扩展名选择加载方法
            suffix = file_path.suffix.lower()
            
            if suffix in ('.yml', '.yaml'):
                rule_content = read_yaml(file_path)
            elif suffix == '.json':
                rule_content = read_json(file_path)
            elif suffix == '.ndjson':
                # NDJSON文件中只取第一个对象
                rules = read_ndjson(file_path)
                if not rules:
                    logger.warning(f"NDJSON文件中没有规则: {file_path}")
                    return None
                rule_content = rules[0]
            else:
                logger.warning(f"不支持的文件格式: {suffix}, 文件: {file_path}")
                return None
            
            # 使用对应的转换器转换规则
            converter = ConverterFactory.get_converter(converter_type)
            return converter.convert(rule_content, str(file_path))
            
        except Exception as e:
            logger.error(f"加载或转换规则失败: {file_path}, 错误: {e}")
            return None