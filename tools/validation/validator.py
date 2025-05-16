#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证器
用于验证规则的语法和格式是否符合要求
"""

import os
import sys
import json
import logging
import argparse
import jsonschema
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set
import datetime

# 添加项目根目录到系统路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from tools.utils.file_utils import read_json, ensure_dir

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('validation.log')
    ]
)
logger = logging.getLogger(__name__)

# 规则模式定义
RULE_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "source": {
            "type": "object",
            "properties": {
                "type": {"type": "string"},
                "id": {"type": "string"},
                "url": {"type": "string"},
                "file_path": {"type": "string"}
            },
            "required": ["type"]
        },
        "tags": {
            "type": "array",
            "items": {"type": "string"}
        },
        "author": {"type": "string"},
        "references": {
            "type": "array",
            "items": {"type": "string"}
        },
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "type": {"type": "string"},
        "status": {"type": "string"},
        "created": {"type": ["string", "null"]},
        "modified": {"type": ["string", "null"]},
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
        "detection": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "condition": {"type": "string"},
                "fields": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            }
        },
        "falsepositives": {
            "type": "array",
            "items": {"type": "string"}
        },
        "level": {"type": "string"},
        "rule_format": {"type": "string"},
        "platforms": {
            "type": "array",
            "items": {"type": "string"}
        },
        "data_sources": {
            "type": "array",
            "items": {"type": "string"}
        }
    },
    "required": ["id", "name", "description", "source", "severity", "detection"]
}

class RuleValidator:
    """规则验证器类"""
    
    def __init__(self, output_file: str = "validation_report.json"):
        """
        初始化规则验证器
        
        Args:
            output_file: 验证报告输出文件
        """
        self.output_file = output_file
        self.report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "total_rules": 0,
            "passed_rules": 0,
            "failed_rules": 0,
            "errors": [],
            "warnings": []
        }
    
    def validate_rule(self, rule_file: Union[str, Path]) -> bool:
        """
        验证单个规则文件
        
        Args:
            rule_file: 规则文件路径
            
        Returns:
            bool: 验证是否通过
        """
        rule_file = Path(rule_file)
        logger.info(f"验证规则文件: {rule_file}")
        
        try:
            # 读取规则文件
            rule = read_json(rule_file)
            
            # 验证规则模式
            self._validate_schema(rule, rule_file)
            
            # 验证规则内容
            self._validate_rule_content(rule, rule_file)
            
            # 验证通过
            self.report["passed_rules"] += 1
            logger.info(f"规则 {rule.get('id', '未知')} 验证通过")
            return True
            
        except Exception as e:
            # 记录错误
            error = {
                "file": str(rule_file),
                "rule_id": rule.get("id", "未知") if "rule" in locals() else "未知",
                "message": str(e)
            }
            self.report["errors"].append(error)
            self.report["failed_rules"] += 1
            
            logger.error(f"规则文件 {rule_file} 验证失败: {e}")
            return False
    
    def _validate_schema(self, rule: Dict, rule_file: Path) -> None:
        """
        验证规则模式
        
        Args:
            rule: 规则内容
            rule_file: 规则文件路径
            
        Raises:
            jsonschema.exceptions.ValidationError: 模式验证错误
        """
        try:
            jsonschema.validate(instance=rule, schema=RULE_SCHEMA)
        except jsonschema.exceptions.ValidationError as e:
            raise ValueError(f"规则模式验证失败: {e}")
    
    def _validate_rule_content(self, rule: Dict, rule_file: Path) -> None:
        """
        验证规则内容
        
        Args:
            rule: 规则内容
            rule_file: 规则文件路径
            
        Raises:
            ValueError: 规则内容验证错误
        """
        # 验证ID格式
        rule_id = rule.get("id", "")
        if not rule_id:
            raise ValueError("规则ID不能为空")
        
        # 验证名称
        name = rule.get("name", "")
        if not name:
            raise ValueError("规则名称不能为空")
        
        # 验证描述
        description = rule.get("description", "")
        if not description:
            raise ValueError("规则描述不能为空")
        
        # 验证检测部分
        detection = rule.get("detection", {})
        if not detection:
            raise ValueError("规则检测部分不能为空")
        
        query = detection.get("query", "")
        if not query:
            raise ValueError("规则检测查询不能为空")
        
        # 验证日期格式
        created = rule.get("created", "")
        if created:
            try:
                datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
            except ValueError:
                self.report["warnings"].append({
                    "file": str(rule_file),
                    "rule_id": rule_id,
                    "message": f"创建日期格式不正确: {created}"
                })
        
        modified = rule.get("modified", "")
        if modified:
            try:
                datetime.datetime.fromisoformat(modified.replace("Z", "+00:00"))
            except ValueError:
                self.report["warnings"].append({
                    "file": str(rule_file),
                    "rule_id": rule_id,
                    "message": f"修改日期格式不正确: {modified}"
                })
    
    def validate_files(self, rule_files: List[Union[str, Path]]) -> Dict:
        """
        验证多个规则文件
        
        Args:
            rule_files: 规则文件路径列表
            
        Returns:
            Dict: 验证报告
        """
        self.report["total_rules"] = len(rule_files)
        
        for rule_file in rule_files:
            self.validate_rule(rule_file)
        
        logger.info(f"验证完成，共 {self.report['total_rules']} 条规则，"
                   f"通过 {self.report['passed_rules']}，"
                   f"失败 {self.report['failed_rules']}")
        
        # 保存验证报告
        self._save_report()
        
        return self.report
    
    def _save_report(self) -> None:
        """
        保存验证报告
        """
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(self.report, f, indent=2, ensure_ascii=False)
            logger.info(f"验证报告已保存到: {self.output_file}")
        except Exception as e:
            logger.error(f"保存验证报告失败: {e}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="规则验证器")
    parser.add_argument('rule_files', nargs='+', help='要验证的规则文件')
    parser.add_argument('--output', '-o', default='validation_report.json', help='验证报告输出文件')
    args = parser.parse_args()
    
    validator = RuleValidator(args.output)
    report = validator.validate_files(args.rule_files)
    
    # 如果有错误，返回非零退出码
    if report["failed_rules"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()