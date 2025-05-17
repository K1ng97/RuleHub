#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
索引生成测试
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

from tools.indexing.indexer import RuleIndexer


class TestRuleIndexer(unittest.TestCase):
    """测试规则索引生成器"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.rules_dir = Path(os.path.join(self.temp_dir, 'rules'))
        self.index_dir = Path(os.path.join(self.temp_dir, 'index'))
        
        # 创建测试目录
        os.makedirs(self.rules_dir, exist_ok=True)
        os.makedirs(self.index_dir, exist_ok=True)
        
        # 创建测试规则目录
        self.sigma_dir = self.rules_dir / 'sigma'
        self.elastic_dir = self.rules_dir / 'elastic'
        os.makedirs(self.sigma_dir, exist_ok=True)
        os.makedirs(self.elastic_dir, exist_ok=True)
        
        # 创建测试规则文件
        self.create_test_rules()
        
        # 创建索引生成器
        self.indexer = RuleIndexer(self.rules_dir, self.index_dir)
    
    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    def create_test_rules(self):
        """创建测试规则文件"""
        # Sigma规则
        sigma_rule1 = {
            "id": "rule_12345678",
            "name": "检测Windows PowerShell执行",
            "description": "检测Windows PowerShell的执行",
            "source": {
                "type": "sigma",
                "id": "sigma-123",
                "url": "https://github.com/SigmaHQ/sigma"
            },
            "tags": ["windows", "powershell", "execution"],
            "severity": "medium",
            "platforms": ["windows"],
            "mitre": {
                "tactics": ["TA0002"],
                "techniques": ["T1059.001"]
            }
        }
        
        sigma_rule2 = {
            "id": "rule_87654321",
            "name": "检测Linux异常登录",
            "description": "检测Linux系统的异常登录行为",
            "source": {
                "type": "sigma",
                "id": "sigma-456",
                "url": "https://github.com/SigmaHQ/sigma"
            },
            "tags": ["linux", "authentication", "lateral_movement"],
            "severity": "high",
            "platforms": ["linux"],
            "mitre": {
                "tactics": ["TA0008"],
                "techniques": ["T1021"]
            }
        }
        
        # Elastic规则
        elastic_rule = {
            "id": "rule_abcdef12",
            "name": "检测网络扫描活动",
            "description": "检测可能的网络扫描活动",
            "source": {
                "type": "elastic",
                "id": "elastic-789",
                "url": "https://github.com/elastic/detection-rules"
            },
            "tags": ["network", "reconnaissance", "scanning"],
            "severity": "low",
            "platforms": ["linux", "windows"],
            "mitre": {
                "tactics": ["TA0007"],
                "techniques": ["T1046"]
            }
        }
        
        # 保存规则文件
        with open(self.sigma_dir / "rule_12345678.json", "w") as f:
            json.dump(sigma_rule1, f)
        
        with open(self.sigma_dir / "rule_87654321.json", "w") as f:
            json.dump(sigma_rule2, f)
        
        with open(self.elastic_dir / "rule_abcdef12.json", "w") as f:
            json.dump(elastic_rule, f)
    
    def test_generate_index(self):
        """测试生成索引"""
        # 生成索引
        stats = self.indexer.generate_index()
        
        # 验证统计信息
        self.assertTrue(stats['success'])
        self.assertEqual(stats['total_sources'], 2)  # sigma和elastic
        self.assertEqual(stats['total_rules'], 3)
        
        # 验证索引文件是否存在
        self.assertTrue((self.index_dir / "rules_index.json").exists())
        self.assertTrue((self.index_dir / "rules_index_compact.json").exists())
        self.assertTrue((self.index_dir / "mitre_index.json").exists())
        self.assertTrue((self.index_dir / "sigma_index.json").exists())
        self.assertTrue((self.index_dir / "elastic_index.json").exists())
        
        # 验证主索引内容
        with open(self.index_dir / "rules_index.json", "r") as f:
            main_index = json.load(f)
        
        self.assertEqual(main_index['meta']['total_rules'], 3)
        self.assertEqual(len(main_index['rules']), 3)
        self.assertEqual(main_index['meta']['sources']['sigma']['count'], 2)
        self.assertEqual(main_index['meta']['sources']['elastic']['count'], 1)
    
    def test_generate_compact_index(self):
        """测试生成精简索引"""
        # 生成索引
        self.indexer.generate_index()
        
        # 验证精简索引内容
        with open(self.index_dir / "rules_index_compact.json", "r") as f:
            compact_index = json.load(f)
        
        self.assertEqual(compact_index['meta']['total_rules'], 3)
        self.assertEqual(len(compact_index['rules']), 3)
        
        # 验证精简规则只包含关键字段
        rule = compact_index['rules'][0]
        self.assertIn('id', rule)
        self.assertIn('name', rule)
        self.assertIn('severity', rule)
        self.assertIn('rule_path', rule)
        self.assertNotIn('description', rule)
        self.assertNotIn('tags', rule)
        self.assertNotIn('mitre', rule)
    
    
    def test_generate_mitre_index(self):
        """测试生成MITRE索引"""
        # 生成索引
        self.indexer.generate_index()
        
        # 验证MITRE索引内容
        with open(self.index_dir / "mitre_index.json", "r") as f:
            mitre_index = json.load(f)
        
        # 验证战术数量
        self.assertEqual(len(mitre_index['tactics']), 3)
        
        # 验证战术包含正确的规则
        ta0002 = mitre_index['tactics']['TA0002']
        self.assertEqual(ta0002['count'], 1)
        self.assertEqual(ta0002['rules'][0]['id'], 'rule_12345678')
        
        # 验证技术数量
        self.assertEqual(len(mitre_index['techniques']), 3)
        
        # 验证技术包含正确的规则
        t1059_001 = mitre_index['techniques']['T1059.001']
        self.assertEqual(t1059_001['count'], 1)
        self.assertEqual(t1059_001['rules'][0]['id'], 'rule_12345678')
    
    def test_search_rules(self):
        """测试搜索规则"""
        # 生成索引
        self.indexer.generate_index()
        
        # 测试按ID搜索
        results = self.indexer.search_rules({"id": "rule_12345678"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['id'], 'rule_12345678')
        
        # 测试按标签搜索
        results = self.indexer.search_rules({"tags": ["windows"]})
        self.assertEqual(len(results), 2)
        
        # 测试按严重程度搜索
        results = self.indexer.search_rules({"severity": "high"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['id'], 'rule_87654321')
        
        # 测试按平台搜索
        results = self.indexer.search_rules({"platforms": ["linux"]})
        self.assertEqual(len(results), 2)
        
        # 测试组合搜索
        results = self.indexer.search_rules({
            "tags": ["linux"],
            "severity": "high"
        })
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['id'], 'rule_87654321')
        
        # 测试无匹配结果
        results = self.indexer.search_rules({
            "tags": ["nonexistent"]
        })
        self.assertEqual(len(results), 0)
    
    def test_create_rule_entry(self):
        """测试创建规则索引条目"""
        # 测试规则
        rule = {
            "id": "test_rule_id",
            "name": "测试规则",
            "description": "这是一个测试规则",
            "severity": "medium",
            "tags": ["test", "example"],
            "mitre": {
                "tactics": ["TA0001"],
                "techniques": ["T1001"]
            }
        }
        
        rule_file = Path("path/to/rule.json")
        
        # 创建索引条目
        entry = self.indexer._create_rule_entry(rule, rule_file)
        
        # 验证结果
        self.assertEqual(entry['id'], "test_rule_id")
        self.assertEqual(entry['name'], "测试规则")
        self.assertEqual(entry['description'], "这是一个测试规则")
        self.assertEqual(entry['severity'], "medium")
        self.assertEqual(entry['tags'], ["test", "example"])
        self.assertEqual(entry['mitre']['tactics'], ["TA0001"])
        self.assertEqual(entry['mitre']['techniques'], ["T1001"])
        self.assertEqual(entry['rule_path'], str(rule_file.relative_to(self.rules_dir.parent)))


if __name__ == '__main__':
    unittest.main()