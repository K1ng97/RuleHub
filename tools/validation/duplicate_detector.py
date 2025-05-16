#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重复规则检测器
用于检测是否存在重复规则
"""

import os
import sys
import json
import logging
import argparse
import difflib
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple, Set

# 添加项目根目录到系统路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from tools.utils.file_utils import read_json, list_files

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('duplicate_detection.log')
    ]
)
logger = logging.getLogger(__name__)


class DuplicateDetector:
    """重复规则检测器类"""
    
    def __init__(self, rules_dir: Union[str, Path] = "rules", similarity_threshold: float = 0.85):
        """
        初始化重复检测器
        
        Args:
            rules_dir: 规则目录
            similarity_threshold: 相似度阈值，高于此值的规则将被视为可能重复
        """
        self.rules_dir = Path(rules_dir)
        self.similarity_threshold = similarity_threshold
        self.existing_rules = {}  # 现有规则字典
        self.report = {
            "duplicates": [],
            "potential_duplicates": [],
            "total_checked": 0
        }
    
    def load_existing_rules(self) -> None:
        """
        加载现有规则
        """
        logger.info(f"从 {self.rules_dir} 加载现有规则")
        
        rule_files = list_files(self.rules_dir, "*.json")
        
        for rule_file in rule_files:
            try:
                rule = read_json(rule_file)
                rule_id = rule.get("id", "")
                
                if rule_id:
                    # 存储规则ID、规则内容和文件路径
                    self.existing_rules[rule_id] = {
                        "content": rule,
                        "file": str(rule_file)
                    }
            except Exception as e:
                logger.warning(f"加载规则 {rule_file} 失败: {e}")
        
        logger.info(f"已加载 {len(self.existing_rules)} 条现有规则")
    
    def check_duplicate_by_id(self, rule: Dict, file_path: str) -> bool:
        """
        通过ID检查重复规则
        
        Args:
            rule: 规则内容
            file_path: 规则文件路径
            
        Returns:
            bool: 是否为重复规则
        """
        rule_id = rule.get("id", "")
        
        if not rule_id:
            logger.warning(f"规则 {file_path} 没有ID")
            return False
        
        # 检查ID是否重复
        if rule_id in self.existing_rules:
            existing_file = self.existing_rules[rule_id]["file"]
            
            # 如果是同一个文件，则不视为重复
            if existing_file == file_path:
                return False
            
            # 记录重复规则
            duplicate = {
                "rule_id": rule_id,
                "new_file": file_path,
                "existing_file": existing_file,
                "reason": "ID重复"
            }
            self.report["duplicates"].append(duplicate)
            
            logger.warning(f"发现重复规则ID: {rule_id}")
            logger.warning(f"  - 新文件: {file_path}")
            logger.warning(f"  - 现有文件: {existing_file}")
            
            return True
        
        return False
    
    def check_duplicate_by_content(self, rule: Dict, file_path: str) -> List[Dict]:
        """
        通过内容检查潜在的重复规则
        
        Args:
            rule: 规则内容
            file_path: 规则文件路径
            
        Returns:
            List[Dict]: 潜在重复规则列表
        """
        potential_duplicates = []
        rule_id = rule.get("id", "")
        
        if not rule_id:
            return potential_duplicates
        
        # 获取重要特征
        detection = rule.get("detection", {})
        query = detection.get("query", "")
        condition = detection.get("condition", "")
        name = rule.get("name", "")
        description = rule.get("description", "")
        
        # 检查所有现有规则
        for existing_id, existing_data in self.existing_rules.items():
            # 跳过自身
            if existing_id == rule_id:
                continue
            
            existing_rule = existing_data["content"]
            existing_file = existing_data["file"]
            
            # 获取现有规则的重要特征
            existing_detection = existing_rule.get("detection", {})
            existing_query = existing_detection.get("query", "")
            existing_condition = existing_detection.get("condition", "")
            existing_name = existing_rule.get("name", "")
            existing_description = existing_rule.get("description", "")
            
            # 计算各特征的相似度
            query_similarity = self._calculate_similarity(query, existing_query)
            name_similarity = self._calculate_similarity(name, existing_name)
            description_similarity = self._calculate_similarity(description, existing_description)
            
            # 综合相似度评分
            overall_similarity = (query_similarity * 0.6 + 
                                 name_similarity * 0.2 + 
                                 description_similarity * 0.2)
            
            # 如果相似度超过阈值，记录为潜在重复
            if overall_similarity >= self.similarity_threshold:
                potential_duplicate = {
                    "rule_id": rule_id,
                    "existing_id": existing_id,
                    "new_file": file_path,
                    "existing_file": existing_file,
                    "similarity": overall_similarity,
                    "details": {
                        "query_similarity": query_similarity,
                        "name_similarity": name_similarity,
                        "description_similarity": description_similarity
                    }
                }
                potential_duplicates.append(potential_duplicate)
                
                logger.info(f"发现潜在重复规则: {rule_id} 与 {existing_id}")
                logger.info(f"  - 总体相似度: {overall_similarity:.4f}")
                logger.info(f"  - 新文件: {file_path}")
                logger.info(f"  - 现有文件: {existing_file}")
        
        return potential_duplicates
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """
        计算两个文本的相似度
        
        Args:
            text1: 第一个文本
            text2: 第二个文本
            
        Returns:
            float: 相似度 (0.0 - 1.0)
        """
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        
        return difflib.SequenceMatcher(None, text1, text2).ratio()
    
    def check_rule(self, rule_file: Union[str, Path]) -> None:
        """
        检查单个规则文件是否有重复
        
        Args:
            rule_file: 规则文件路径
        """
        rule_file = Path(rule_file)
        logger.info(f"检查规则文件: {rule_file}")
        
        try:
            rule = read_json(rule_file)
            
            # 通过ID检查重复
            is_duplicate = self.check_duplicate_by_id(rule, str(rule_file))
            
            # 如果不是直接ID重复，检查内容相似度
            if not is_duplicate:
                potential_duplicates = self.check_duplicate_by_content(rule, str(rule_file))
                if potential_duplicates:
                    self.report["potential_duplicates"].extend(potential_duplicates)
            
            self.report["total_checked"] += 1
            
        except Exception as e:
            logger.error(f"检查规则 {rule_file} 失败: {e}")
    
    def check_files(self, rule_files: List[Union[str, Path]]) -> Dict:
        """
        检查多个规则文件是否有重复
        
        Args:
            rule_files: 规则文件路径列表
            
        Returns:
            Dict: 检测报告
        """
        # 首先加载现有规则
        self.load_existing_rules()
        
        for rule_file in rule_files:
            self.check_rule(rule_file)
        
        # 保存报告
        self._save_report()
        
        # 打印报告摘要
        logger.info(f"检查完成，共检查 {self.report['total_checked']} 条规则")
        logger.info(f"发现 {len(self.report['duplicates'])} 条重复规则")
        logger.info(f"发现 {len(self.report['potential_duplicates'])} 条潜在重复规则")
        
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
            # 如果文件不存在或解析失败，创建新报告
            validation_report = {}
        
        # 添加重复检测结果
        validation_report["duplicate_check"] = {
            "total_checked": self.report["total_checked"],
            "duplicates": len(self.report["duplicates"]),
            "potential_duplicates": len(self.report["potential_duplicates"]),
            "duplicate_details": self.report["duplicates"],
            "potential_duplicate_details": self.report["potential_duplicates"]
        }
        
        # 将错误添加到主报告中
        if "errors" not in validation_report:
            validation_report["errors"] = []
            
        for duplicate in self.report["duplicates"]:
            error = {
                "rule_id": duplicate["rule_id"],
                "file": duplicate["new_file"],
                "message": f"规则ID重复: 与 {duplicate['existing_file']} 冲突"
            }
            validation_report["errors"].append(error)
        
        # 将警告添加到主报告中
        if "warnings" not in validation_report:
            validation_report["warnings"] = []
            
        for potential in self.report["potential_duplicates"]:
            warning = {
                "rule_id": potential["rule_id"],
                "file": potential["new_file"],
                "message": f"潜在重复规则: 与 {potential['existing_id']} 相似度为 {potential['similarity']:.4f}"
            }
            validation_report["warnings"].append(warning)
        
        # 保存报告
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(validation_report, f, indent=2, ensure_ascii=False)
            logger.info(f"重复检测报告已保存到: {report_file}")
        except Exception as e:
            logger.error(f"保存报告失败: {e}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="规则重复检测器")
    parser.add_argument('rule_files', nargs='+', help='要检查的规则文件')
    parser.add_argument('--rules-dir', default='rules', help='规则目录')
    parser.add_argument('--threshold', type=float, default=0.85, help='相似度阈值')
    args = parser.parse_args()
    
    detector = DuplicateDetector(args.rules_dir, args.threshold)
    report = detector.check_files(args.rule_files)
    
    # 如果有重复规则，返回非零退出码
    if report["duplicates"]:
        sys.exit(1)


if __name__ == "__main__":
    main()