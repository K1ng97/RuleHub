#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE ATT&CK映射验证器
用于验证和更新规则的MITRE ATT&CK映射
"""

import os
import sys
import json
import logging
import argparse
import re
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set
from datetime import datetime

# 添加项目根目录到系统路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from tools.utils.file_utils import read_json, write_json

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('mitre_mapping.log')
    ]
)
logger = logging.getLogger(__name__)


class MitreMapper:
    """MITRE ATT&CK映射器类"""
    
    def __init__(self, mitre_cache_file: str = "mitre_attack_cache.json", update_cache: bool = False):
        """
        初始化MITRE映射器
        
        Args:
            mitre_cache_file: MITRE ATT&CK缓存文件路径
            update_cache: 是否更新缓存
        """
        self.mitre_cache_file = mitre_cache_file
        self.mitre_data = self._load_mitre_data(update_cache)
        self.report = {
            "mapped_rules": 0,
            "updated_mappings": 0,
            "invalid_mappings": 0,
            "mapping_errors": []
        }
    
    def _load_mitre_data(self, update_cache: bool) -> Dict:
        """
        加载MITRE ATT&CK数据
        
        Args:
            update_cache: 是否更新缓存
            
        Returns:
            Dict: MITRE ATT&CK数据
        """
        # 尝试从缓存加载
        if os.path.exists(self.mitre_cache_file) and not update_cache:
            try:
                with open(self.mitre_cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                # 检查缓存是否过期（超过30天）
                cache_date = datetime.fromisoformat(cache_data.get("cache_date", "2000-01-01"))
                now = datetime.now()
                
                if (now - cache_date).days < 30:
                    logger.info(f"从缓存加载MITRE ATT&CK数据: {self.mitre_cache_file}")
                    return cache_data
                else:
                    logger.info("MITRE ATT&CK缓存已过期，将更新")
            except Exception as e:
                logger.warning(f"读取MITRE ATT&CK缓存失败: {e}")
        
        # 从API获取最新数据
        logger.info("从MITRE ATT&CK API获取最新数据")
        mitre_data = self._fetch_mitre_data()
        
        # 保存到缓存
        try:
            with open(self.mitre_cache_file, 'w', encoding='utf-8') as f:
                json.dump(mitre_data, f, indent=2, ensure_ascii=False)
            logger.info(f"MITRE ATT&CK数据已缓存到: {self.mitre_cache_file}")
        except Exception as e:
            logger.warning(f"保存MITRE ATT&CK缓存失败: {e}")
        
        return mitre_data
    
    def _fetch_mitre_data(self) -> Dict:
        """
        从MITRE ATT&CK API获取数据
        
        Returns:
            Dict: MITRE ATT&CK数据
        """
        mitre_data = {
            "cache_date": datetime.now().isoformat(),
            "tactics": {},
            "techniques": {},
            "subtechniques": {}
        }
        
        try:
            # 获取企业矩阵数据
            enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = requests.get(enterprise_url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # 处理战术
            tactics = [obj for obj in data["objects"] if obj["type"] == "x-mitre-tactic"]
            for tactic in tactics:
                tactic_id = tactic.get("external_references", [{}])[0].get("external_id", "")
                if tactic_id:
                    mitre_data["tactics"][tactic_id] = {
                        "name": tactic.get("name", ""),
                        "description": tactic.get("description", "")
                    }
            
            # 处理技术
            techniques = [obj for obj in data["objects"] if obj["type"] == "attack-pattern"]
            for technique in techniques:
                tech_id = technique.get("external_references", [{}])[0].get("external_id", "")
                if tech_id:
                    # 确定是技术还是子技术
                    if "." in tech_id:
                        parent_id, sub_id = tech_id.split(".")
                        mitre_data["subtechniques"][tech_id] = {
                            "name": technique.get("name", ""),
                            "description": technique.get("description", ""),
                            "parent": parent_id
                        }
                    else:
                        mitre_data["techniques"][tech_id] = {
                            "name": technique.get("name", ""),
                            "description": technique.get("description", ""),
                            "tactics": []
                        }
                        
                        # 获取技术对应的战术
                        kill_chain_phases = technique.get("kill_chain_phases", [])
                        for phase in kill_chain_phases:
                            phase_name = phase.get("phase_name", "")
                            # 查找对应的战术ID
                            for tactic_id, tactic_info in mitre_data["tactics"].items():
                                if phase_name.lower() in tactic_info["name"].lower().replace(" ", "-"):
                                    mitre_data["techniques"][tech_id]["tactics"].append(tactic_id)
                                    break
            
            logger.info(f"已获取 {len(mitre_data['tactics'])} 个战术, {len(mitre_data['techniques'])} 个技术, "
                       f"{len(mitre_data['subtechniques'])} 个子技术")
            
            return mitre_data
            
        except Exception as e:
            logger.error(f"获取MITRE ATT&CK数据失败: {e}")
            # 返回空数据结构
            return {
                "cache_date": datetime.now().isoformat(),
                "tactics": {},
                "techniques": {},
                "subtechniques": {}
            }
    
    def validate_mapping(self, rule: Dict) -> Dict:
        """
        验证规则的MITRE ATT&CK映射
        
        Args:
            rule: 规则内容
            
        Returns:
            Dict: 验证结果
        """
        rule_id = rule.get("id", "未知")
        mitre = rule.get("mitre", {})
        tactics = mitre.get("tactics", [])
        techniques = mitre.get("techniques", [])
        
        result = {
            "rule_id": rule_id,
            "valid_tactics": [],
            "invalid_tactics": [],
            "valid_techniques": [],
            "invalid_techniques": [],
            "suggested_tactics": [],
            "suggested_techniques": []
        }
        
        # 验证战术
        for tactic in tactics:
            if tactic in self.mitre_data["tactics"]:
                result["valid_tactics"].append(tactic)
            else:
                result["invalid_tactics"].append(tactic)
        
        # 验证技术
        for technique in techniques:
            if technique in self.mitre_data["techniques"] or technique in self.mitre_data["subtechniques"]:
                result["valid_techniques"].append(technique)
            else:
                result["invalid_techniques"].append(technique)
        
        # 提供建议
        # 如果有有效技术但没有战术，建议添加技术对应的战术
        if result["valid_techniques"] and not result["valid_tactics"]:
            for technique in result["valid_techniques"]:
                if technique in self.mitre_data["techniques"]:
                    for tactic_id in self.mitre_data["techniques"][technique]["tactics"]:
                        if tactic_id not in result["suggested_tactics"]:
                            result["suggested_tactics"].append(tactic_id)
        
        # 如果有有效战术但没有技术，建议可能的技术
        if result["valid_tactics"] and not result["valid_techniques"]:
            for tactic in result["valid_tactics"]:
                for tech_id, tech_info in self.mitre_data["techniques"].items():
                    if tactic in tech_info["tactics"] and tech_id not in result["suggested_techniques"]:
                        result["suggested_techniques"].append(tech_id)
        
        return result
    
    def update_mapping(self, rule: Dict, validation: Dict) -> Dict:
        """
        更新规则的MITRE ATT&CK映射
        
        Args:
            rule: 规则内容
            validation: 验证结果
            
        Returns:
            Dict: 更新后的规则
        """
        if not rule.get("mitre"):
            rule["mitre"] = {}
        
        # 移除无效的战术和技术
        if "tactics" in rule["mitre"]:
            rule["mitre"]["tactics"] = validation["valid_tactics"]
        
        if "techniques" in rule["mitre"]:
            rule["mitre"]["techniques"] = validation["valid_techniques"]
        
        # 添加建议的战术和技术
        if validation["suggested_tactics"]:
            if "tactics" not in rule["mitre"]:
                rule["mitre"]["tactics"] = []
            
            for tactic in validation["suggested_tactics"]:
                if tactic not in rule["mitre"]["tactics"]:
                    rule["mitre"]["tactics"].append(tactic)
        
        if validation["suggested_techniques"]:
            if "techniques" not in rule["mitre"]:
                rule["mitre"]["techniques"] = []
            
            # 仅添加前5个建议的技术，避免过多
            for technique in validation["suggested_techniques"][:5]:
                if technique not in rule["mitre"]["techniques"]:
                    rule["mitre"]["techniques"].append(technique)
        
        return rule
    
    def process_rule(self, rule_file: Union[str, Path], update_rule: bool = False) -> Dict:
        """
        处理单个规则文件
        
        Args:
            rule_file: 规则文件路径
            update_rule: 是否更新规则文件
            
        Returns:
            Dict: 处理结果
        """
        rule_file = Path(rule_file)
        logger.info(f"处理规则文件: {rule_file}")
        
        try:
            # 读取规则文件
            rule = read_json(rule_file)
            rule_id = rule.get("id", "未知")
            
            # 验证MITRE映射
            validation = self.validate_mapping(rule)
            
            # 更新统计信息
            self.report["mapped_rules"] += 1
            
            if validation["invalid_tactics"] or validation["invalid_techniques"]:
                self.report["invalid_mappings"] += 1
                
                # 记录错误
                error = {
                    "rule_id": rule_id,
                    "file": str(rule_file),
                    "invalid_tactics": validation["invalid_tactics"],
                    "invalid_techniques": validation["invalid_techniques"]
                }
                self.report["mapping_errors"].append(error)
            
            # 如果需要更新规则并且有无效映射或建议
            if update_rule and (validation["invalid_tactics"] or validation["invalid_techniques"] or 
                               validation["suggested_tactics"] or validation["suggested_techniques"]):
                # 更新规则映射
                updated_rule = self.update_mapping(rule, validation)
                
                # 保存更新后的规则
                write_json(updated_rule, rule_file)
                
                self.report["updated_mappings"] += 1
                logger.info(f"已更新规则 {rule_id} 的MITRE映射")
            
            return validation
            
        except Exception as e:
            logger.error(f"处理规则 {rule_file} 失败: {e}")
            
            # 记录错误
            error = {
                "rule_id": "未知",
                "file": str(rule_file),
                "error": str(e)
            }
            self.report["mapping_errors"].append(error)
            
            return {
                "rule_id": "未知",
                "error": str(e)
            }
    
    def process_files(self, rule_files: List[Union[str, Path]], update_rules: bool = False) -> Dict:
        """
        处理多个规则文件
        
        Args:
            rule_files: 规则文件路径列表
            update_rules: 是否更新规则文件
            
        Returns:
            Dict: 处理报告
        """
        for rule_file in rule_files:
            self.process_rule(rule_file, update_rules)
        
        # 保存报告
        self._save_report()
        
        # 打印报告摘要
        logger.info(f"处理完成，共处理 {self.report['mapped_rules']} 条规则")
        logger.info(f"无效映射: {self.report['invalid_mappings']} 条")
        logger.info(f"已更新映射: {self.report['updated_mappings']} 条")
        
        return self.report
    
    def _save_report(self) -> None:
        """
        保存报告到验证报告文件
        """
        # 读取现有验证报告
        report_file = "validation_report.json"
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                validation_report = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            validation_report = {}
        
        # 添加MITRE映射结果
        validation_report["mitre_mapping"] = {
            "mapped_rules": self.report["mapped_rules"],
            "invalid_mappings": self.report["invalid_mappings"],
            "updated_mappings": self.report["updated_mappings"]
        }
        
        # 将错误添加到主报告中
        if "errors" not in validation_report:
            validation_report["errors"] = []
            
        for error in self.report["mapping_errors"]:
            if "error" in error:
                # 处理异常错误
                error_entry = {
                    "rule_id": error["rule_id"],
                    "file": error["file"],
                    "message": f"MITRE映射错误: {error['error']}"
                }
                validation_report["errors"].append(error_entry)
            else:
                # 处理无效映射
                tactics = ", ".join(error["invalid_tactics"]) if error["invalid_tactics"] else ""
                techniques = ", ".join(error["invalid_techniques"]) if error["invalid_techniques"] else ""
                
                if tactics or techniques:
                    message = "无效的MITRE映射: "
                    if tactics:
                        message += f"战术 [{tactics}]"
                    if tactics and techniques:
                        message += ", "
                    if techniques:
                        message += f"技术 [{techniques}]"
                    
                    error_entry = {
                        "rule_id": error["rule_id"],
                        "file": error["file"],
                        "message": message
                    }
                    validation_report["errors"].append(error_entry)
        
        # 保存报告
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(validation_report, f, indent=2, ensure_ascii=False)
            logger.info(f"MITRE映射报告已保存到: {report_file}")
        except Exception as e:
            logger.error(f"保存报告失败: {e}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="MITRE ATT&CK映射验证器")
    parser.add_argument('rule_files', nargs='+', help='要验证的规则文件')
    parser.add_argument('--update-cache', action='store_true', help='更新MITRE ATT&CK缓存')
    parser.add_argument('--update-rules', action='store_true', help='更新规则的MITRE映射')
    parser.add_argument('--cache-file', default='mitre_attack_cache.json', help='MITRE ATT&CK缓存文件路径')
    args = parser.parse_args()
    
    mapper = MitreMapper(args.cache_file, args.update_cache)
    mapper.process_files(args.rule_files, args.update_rules)


if __name__ == "__main__":
    main()