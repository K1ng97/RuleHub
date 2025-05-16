#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则性能分析器
用于分析规则的性能影响
"""

import os
import sys
import json
import logging
import argparse
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set

# 添加项目根目录到系统路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from tools.utils.file_utils import read_json

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('performance_analysis.log')
    ]
)
logger = logging.getLogger(__name__)


class PerformanceAnalyzer:
    """规则性能分析器类"""
    
    def __init__(self):
        """
        初始化性能分析器
        """
        self.report = {
            "analyzed_rules": 0,
            "high_impact_rules": [],
            "medium_impact_rules": [],
            "low_impact_rules": [],
            "overall_impact": "low"
        }
        
        # 性能影响关键词和权重
        self.performance_keywords = {
            # 高影响关键词
            "high": {
                r"\bfull(\s+|_)scan\b": 10,
                r"\ball(\s+|_)events\b": 9,
                r"\bunbounded\b": 9,
                r"\bindex(\s+|_)all\b": 8,
                r"\.{3}": 8,  # 省略号（通配符）
                r"\b(wildcard|glob)(s?)\b": 8,
                r"\*": 7
            },
            # 中等影响关键词
            "medium": {
                r"\bregex\b": 6,
                r"\blive(\s+|_)(search|query)\b": 6,
                r"\bcontains\b": 5,
                r"\bgroup\s+by\b": 5,
                r"\bsort\b": 5,
                r"\border\s+by\b": 5,
                r"\blarge\s+time\s+range\b": 5,
                r"\baggregate\b": 4,
                r"\bjoin\b": 4
            },
            # 低影响关键词
            "low": {
                r"\bprefixed\b": 3,
                r"\bequals\b": 2,
                r"\bis\b": 2,
                r"\bexact\b": 1,
                r"\bspecific\b": 1,
                r"\bindexed(\s+|_)field\b": 1
            }
        }
        
        # 数据源影响权重
        self.datasource_impact = {
            "network": 6,
            "sysmon": 4,
            "windows": 5,
            "authentication": 3,
            "firewalls": 6,
            "proxy": 5,
            "all_logs": 8,
            "events": 4
        }
    
    def analyze_rule(self, rule_file: Union[str, Path]) -> Dict:
        """
        分析单个规则文件的性能影响
        
        Args:
            rule_file: 规则文件路径
            
        Returns:
            Dict: 性能分析结果
        """
        rule_file = Path(rule_file)
        logger.info(f"分析规则文件: {rule_file}")
        
        try:
            # 读取规则文件
            rule = read_json(rule_file)
            rule_id = rule.get("id", "未知")
            
            # 获取规则查询
            detection = rule.get("detection", {})
            query = detection.get("query", "")
            condition = detection.get("condition", "")
            
            # 分析性能影响
            impact_score = 0
            impact_factors = []
            
            # 分析查询中的关键词
            for impact_level, keywords in self.performance_keywords.items():
                for keyword, weight in keywords.items():
                    matches = len(re.findall(keyword, query, re.IGNORECASE))
                    if matches > 0:
                        impact_score += matches * weight
                        impact_factors.append({
                            "factor": re.sub(r'\\b|\\s|\+|_|\(|\)', '', keyword),
                            "matches": matches,
                            "weight": weight,
                            "impact": impact_level
                        })
            
            # 分析数据源
            data_sources = rule.get("data_sources", [])
            for source in data_sources:
                source_lower = source.lower()
                for ds_key, ds_weight in self.datasource_impact.items():
                    if ds_key in source_lower:
                        impact_score += ds_weight
                        impact_factors.append({
                            "factor": f"数据源: {source}",
                            "weight": ds_weight,
                            "impact": "数据源影响"
                        })
            
            # 确定性能影响级别
            impact_level = "low"
            if impact_score >= 20:
                impact_level = "high"
            elif impact_score >= 10:
                impact_level = "medium"
            
            # 生成分析结果
            result = {
                "rule_id": rule_id,
                "file": str(rule_file),
                "impact_score": impact_score,
                "impact_level": impact_level,
                "impact_factors": impact_factors
            }
            
            # 更新报告
            self.report["analyzed_rules"] += 1
            
            if impact_level == "high":
                self.report["high_impact_rules"].append(result)
            elif impact_level == "medium":
                self.report["medium_impact_rules"].append(result)
            else:
                self.report["low_impact_rules"].append(result)
            
            logger.info(f"规则 {rule_id} 性能影响分析完成，影响级别: {impact_level}，分数: {impact_score}")
            
            return result
            
        except Exception as e:
            logger.error(f"分析规则 {rule_file} 失败: {e}")
            return {
                "rule_id": "未知",
                "file": str(rule_file),
                "error": str(e)
            }
    
    def analyze_files(self, rule_files: List[Union[str, Path]]) -> Dict:
        """
        分析多个规则文件的性能影响
        
        Args:
            rule_files: 规则文件路径列表
            
        Returns:
            Dict: 性能分析报告
        """
        for rule_file in rule_files:
            self.analyze_rule(rule_file)
        
        # 确定整体性能影响
        if len(self.report["high_impact_rules"]) > 0:
            self.report["overall_impact"] = "high"
        elif len(self.report["medium_impact_rules"]) > len(rule_files) * 0.5:
            self.report["overall_impact"] = "medium"
        
        # 保存分析报告
        self._save_report()
        
        # 打印报告摘要
        logger.info(f"分析完成，共分析 {self.report['analyzed_rules']} 条规则")
        logger.info(f"高影响规则: {len(self.report['high_impact_rules'])} 条")
        logger.info(f"中影响规则: {len(self.report['medium_impact_rules'])} 条")
        logger.info(f"低影响规则: {len(self.report['low_impact_rules'])} 条")
        logger.info(f"整体性能影响: {self.report['overall_impact']}")
        
        return self.report
    
    def _save_report(self) -> None:
        """
        保存分析报告到验证报告文件
        """
        # 读取现有验证报告
        report_file = "validation_report.json"
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                validation_report = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            validation_report = {}
        
        # 添加性能分析结果
        validation_report["performance_impact"] = {
            "overall_impact": self.report["overall_impact"],
            "high_impact_rules": self.report["high_impact_rules"],
            "medium_impact_rules": len(self.report["medium_impact_rules"]),
            "low_impact_rules": len(self.report["low_impact_rules"])
        }
        
        # 将性能警告添加到主报告中
        if "warnings" not in validation_report:
            validation_report["warnings"] = []
        
        # 添加高影响规则的警告
        for rule in self.report["high_impact_rules"]:
            warning = {
                "rule_id": rule["rule_id"],
                "file": rule["file"],
                "message": f"高性能影响规则: 分数 {rule['impact_score']}"
            }
            validation_report["warnings"].append(warning)
        
        # 保存报告
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(validation_report, f, indent=2, ensure_ascii=False)
            logger.info(f"性能分析报告已保存到: {report_file}")
        except Exception as e:
            logger.error(f"保存报告失败: {e}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="规则性能分析器")
    parser.add_argument('rule_files', nargs='+', help='要分析的规则文件')
    args = parser.parse_args()
    
    analyzer = PerformanceAnalyzer()
    analyzer.analyze_files(args.rule_files)


if __name__ == "__main__":
    main()