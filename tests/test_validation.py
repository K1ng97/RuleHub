#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则验证测试
"""

import os
import sys
import json
import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

# 添加项目根目录到Python路径，以便导入模块
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.validation.validator import Validator, ValidationResult, ValidationLevel
from tools.validation.duplicate_detector import DuplicateDetector
from tools.validation.mitre_mapper import MitreMapper


class TestValidator(unittest.TestCase):
    """测试规则验证器"""
    
    def setUp(self):
        """测试前准备"""
        self.validator = Validator()
        
        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()
        self.rules_dir = os.path.join(self.temp_dir, 'rules')
        os.makedirs(self.rules_dir, exist_ok=True)
    
    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    def test_validate_rule_id(self):
        """测试验证规则ID"""
        # 测试有效ID
        rule = {"id": "rule_12345678"}
        results = self.validator.validate_rule_id(rule)
        self.assertEqual(len(results), 0)
        
        # 测试无ID
        rule = {"name": "测试规则"}
        results = self.validator.validate_rule_id(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.ERROR)
        
        # 测试ID格式不正确
        rule = {"id": "invalid id with spaces"}
        results = self.validator.validate_rule_id(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.ERROR)
    
    def test_validate_rule_name(self):
        """测试验证规则名称"""
        # 测试有效名称
        rule = {"name": "有效的规则名称"}
        results = self.validator.validate_rule_name(rule)
        self.assertEqual(len(results), 0)
        
        # 测试无名称
        rule = {"id": "rule_12345678"}
        results = self.validator.validate_rule_name(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.ERROR)
        
        # 测试名称过短
        rule = {"name": "短"}
        results = self.validator.validate_rule_name(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.WARNING)
    
    def test_validate_rule_severity(self):
        """测试验证规则严重程度"""
        # 测试有效严重程度
        rule = {"severity": "high"}
        results = self.validator.validate_rule_severity(rule)
        self.assertEqual(len(results), 0)
        
        # 测试无严重程度
        rule = {"id": "rule_12345678"}
        results = self.validator.validate_rule_severity(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.WARNING)
        
        # 测试无效严重程度
        rule = {"severity": "invalid"}
        results = self.validator.validate_rule_severity(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.ERROR)
    
    def test_validate_rule_tags(self):
        """测试验证规则标签"""
        # 测试有效标签
        rule = {"tags": ["windows", "powershell", "execution"]}
        results = self.validator.validate_rule_tags(rule)
        self.assertEqual(len(results), 0)
        
        # 测试无标签
        rule = {"id": "rule_12345678"}
        results = self.validator.validate_rule_tags(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.WARNING)
        
        # 测试标签过少
        rule = {"tags": ["windows"]}
        results = self.validator.validate_rule_tags(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.WARNING)
    
    def test_validate_rule_mitre(self):
        """测试验证规则MITRE映射"""
        # 测试有效MITRE映射
        rule = {
            "mitre": {
                "tactics": ["TA0001", "TA0002"],
                "techniques": ["T1059.001", "T1021"]
            }
        }
        results = self.validator.validate_rule_mitre(rule)
        self.assertEqual(len(results), 0)
        
        # 测试无MITRE映射
        rule = {"id": "rule_12345678"}
        results = self.validator.validate_rule_mitre(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.INFO)
        
        # 测试无效MITRE战术
        rule = {
            "mitre": {
                "tactics": ["invalid"],
                "techniques": ["T1059.001"]
            }
        }
        results = self.validator.validate_rule_mitre(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.WARNING)
    
    def test_validate_rule_detection(self):
        """测试验证规则检测部分"""
        # 测试有效检测
        rule = {
            "detection": {
                "query": "process_name = 'powershell.exe'",
                "condition": "selection"
            }
        }
        results = self.validator.validate_rule_detection(rule)
        self.assertEqual(len(results), 0)
        
        # 测试无检测
        rule = {"id": "rule_12345678"}
        results = self.validator.validate_rule_detection(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.WARNING)
        
        # 测试无查询
        rule = {
            "detection": {
                "condition": "selection"
            }
        }
        results = self.validator.validate_rule_detection(rule)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.WARNING)
    
    def test_validate_rule(self):
        """测试验证整个规则"""
        # 测试有效规则
        rule = {
            "id": "rule_12345678",
            "name": "检测PowerShell执行",
            "description": "检测PowerShell的执行",
            "severity": "medium",
            "tags": ["windows", "powershell", "execution"],
            "mitre": {
                "tactics": ["TA0002"],
                "techniques": ["T1059.001"]
            },
            "detection": {
                "query": "process_name = 'powershell.exe'",
                "condition": "selection"
            }
        }
        results = self.validator.validate_rule(rule)
        
        # 应该没有错误级别的验证结果
        errors = [r for r in results if r.level == ValidationLevel.ERROR]
        self.assertEqual(len(errors), 0)
    
    def test_validate_file(self):
        """测试验证规则文件"""
        # 创建测试规则文件
        rule = {
            "id": "rule_12345678",
            "name": "检测PowerShell执行",
            "description": "检测PowerShell的执行",
            "severity": "medium",
            "tags": ["windows", "powershell", "execution"],
            "mitre": {
                "tactics": ["TA0002"],
                "techniques": ["T1059.001"]
            },
            "detection": {
                "query": "process_name = 'powershell.exe'",
                "condition": "selection"
            }
        }
        
        rule_file = os.path.join(self.rules_dir, "test_rule.json")
        with open(rule_file, "w") as f:
            json.dump(rule, f)
        
        # 验证文件
        results = self.validator.validate_file(rule_file)
        
        # 应该没有错误级别的验证结果
        errors = [r for r in results if r.level == ValidationLevel.ERROR]
        self.assertEqual(len(errors), 0)
        
        # 测试无效JSON文件
        invalid_file = os.path.join(self.rules_dir, "invalid.json")
        with open(invalid_file, "w") as f:
            f.write("This is not valid JSON")
        
        results = self.validator.validate_file(invalid_file)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].level, ValidationLevel.ERROR)
    
    def test_validate_directory(self):
        """测试验证规则目录"""
        # 创建测试规则文件
        rule1 = {
            "id": "rule_12345678",
            "name": "检测PowerShell执行",
            "description": "检测PowerShell的执行",
            "severity": "medium",
            "tags": ["windows", "powershell", "execution"],
            "mitre": {
                "tactics": ["TA0002"],
                "techniques": ["T1059.001"]
            },
            "detection": {
                "query": "process_name = 'powershell.exe'",
                "condition": "selection"
            }
        }
        
        rule2 = {
            "id": "rule_87654321",
            "name": "检测异常登录",
            "description": "检测异常登录行为",
            "severity": "high",
            "tags": ["windows", "authentication"],
            "mitre": {
                "tactics": ["TA0008"],
                "techniques": ["T1078"]
            },
            "detection": {
                "query": "event_id = 4624 AND logon_type = 3",
                "condition": "selection"
            }
        }
        
        with open(os.path.join(self.rules_dir, "rule1.json"), "w") as f:
            json.dump(rule1, f)
        
        with open(os.path.join(self.rules_dir, "rule2.json"), "w") as f:
            json.dump(rule2, f)
        
        # 创建一个无效文件
        with open(os.path.join(self.rules_dir, "invalid.json"), "w") as f:
            f.write("This is not valid JSON")
        
        # 验证目录
        results = self.validator.validate_directory(self.rules_dir)
        
        # 应该有一个错误（无效文件）
        errors = [r for r in results if r.level == ValidationLevel.ERROR]
        self.assertEqual(len(errors), 1)
        
        # 总共应该有多个验证结果
        self.assertGreater(len(results), 1)


class TestDuplicateDetector(unittest.TestCase):
    """测试重复规则检测器"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.rules_dir = os.path.join(self.temp_dir, 'rules')
        os.makedirs(self.rules_dir, exist_ok=True)
        
        # 创建重复检测器
        self.detector = DuplicateDetector(self.rules_dir)
    
    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    def test_detect_duplicates(self):
        """测试检测重复规则"""
        # 创建两个内容相似的规则
        rule1 = {
            "id": "rule_12345678",
            "name": "检测PowerShell执行",
            "description": "检测PowerShell的执行",
            "detection": {
                "query": "process_name = 'powershell.exe'",
                "condition": "selection"
            }
        }
        
        rule2 = {
            "id": "rule_87654321",
            "name": "检测PowerShell命令执行",
            "description": "检测PowerShell命令的执行",
            "detection": {
                "query": "process_name = 'powershell.exe'",
                "condition": "selection"
            }
        }
        
        # 创建一个不同的规则
        rule3 = {
            "id": "rule_abcdef12",
            "name": "检测异常登录",
            "description": "检测异常登录行为",
            "detection": {
                "query": "event_id = 4624 AND logon_type = 3",
                "condition": "selection"
            }
        }
        
        # 保存规则文件
        with open(os.path.join(self.rules_dir, "rule1.json"), "w") as f:
            json.dump(rule1, f)
        
        with open(os.path.join(self.rules_dir, "rule2.json"), "w") as f:
            json.dump(rule2, f)
        
        with open(os.path.join(self.rules_dir, "rule3.json"), "w") as f:
            json.dump(rule3, f)
        
        # 检测重复
        duplicates = self.detector.detect_duplicates()
        
        # 应该检测到一组重复（rule1和rule2）
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(len(duplicates[0]), 2)


class TestMitreMapper(unittest.TestCase):
    """测试MITRE映射器"""
    
    def setUp(self):
        """测试前准备"""
        self.mapper = MitreMapper()
    
    def test_validate_tactic(self):
        """测试验证战术ID"""
        # 测试有效战术ID
        self.assertTrue(self.mapper.validate_tactic("TA0001"))
        self.assertTrue(self.mapper.validate_tactic("TA0002"))
        self.assertTrue(self.mapper.validate_tactic("TA0003"))
        
        # 测试无效战术ID
        self.assertFalse(self.mapper.validate_tactic("invalid"))
        self.assertFalse(self.mapper.validate_tactic("TA9999"))
        self.assertFalse(self.mapper.validate_tactic("T0001"))
    
    def test_validate_technique(self):
        """测试验证技术ID"""
        # 测试有效技术ID
        self.assertTrue(self.mapper.validate_technique("T1059"))
        self.assertTrue(self.mapper.validate_technique("T1059.001"))
        
        # 测试无效技术ID
        self.assertFalse(self.mapper.validate_technique("invalid"))
        self.assertFalse(self.mapper.validate_technique("T9999"))
        self.assertFalse(self.mapper.validate_technique("TA1059"))
    
    def test_get_tactic_name(self):
        """测试获取战术名称"""
        # 测试有效战术ID
        self.assertEqual(self.mapper.get_tactic_name("TA0001"), "Initial Access")
        self.assertEqual(self.mapper.get_tactic_name("TA0002"), "Execution")
        
        # 测试无效战术ID
        self.assertIsNone(self.mapper.get_tactic_name("invalid"))
    
    def test_get_technique_name(self):
        """测试获取技术名称"""
        # 测试有效技术ID
        self.assertEqual(self.mapper.get_technique_name("T1059"), "Command and Scripting Interpreter")
        self.assertEqual(self.mapper.get_technique_name("T1059.001"), "PowerShell")
        
        # 测试无效技术ID
        self.assertIsNone(self.mapper.get_technique_name("invalid"))
    
    def test_suggest_tactics(self):
        """测试建议战术"""
        # 测试关键词建议
        tactics = self.mapper.suggest_tactics("execution")
        self.assertIn("TA0002", tactics)
        
        tactics = self.mapper.suggest_tactics("lateral movement")
        self.assertIn("TA0008", tactics)
    
    def test_suggest_techniques(self):
        """测试建议技术"""
        # 测试关键词建议
        techniques = self.mapper.suggest_techniques("powershell")
        self.assertIn("T1059.001", techniques)
        
        techniques = self.mapper.suggest_techniques("registry")
        self.assertIn("T1112", techniques)


if __name__ == '__main__':
    unittest.main()