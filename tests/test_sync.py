#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则同步机制测试
"""

import os
import sys
import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

# 添加项目根目录到Python路径，以便导入模块
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.sync.sync_manager import SyncManager
from tools.sync.repo_handler import RepoHandler
from tools.sync.rule_converter import ConverterFactory, SigmaConverter


class TestRepoHandler(unittest.TestCase):
    """测试仓库处理器"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.clone_path = os.path.join(self.temp_dir, 'repos')
        self.repo_handler = RepoHandler(self.clone_path, timeout=10)
    
    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    @patch('tools.sync.repo_handler.git.Repo')
    def test_clone_repo(self, mock_repo):
        """测试克隆仓库"""
        # 模拟Git操作
        mock_instance = MagicMock()
        mock_repo.clone_from.return_value = mock_instance
        mock_instance.head.commit.hexsha = 'abcd1234'
        
        # 测试克隆仓库
        success, repo_info = self.repo_handler.clone_repo(
            'test_repo',
            'https://github.com/test/repo.git',
            'main'
        )
        
        # 验证结果
        self.assertTrue(success)
        self.assertEqual(repo_info.name, 'test_repo')
        self.assertEqual(repo_info.url, 'https://github.com/test/repo.git')
        self.assertEqual(repo_info.branch, 'main')
        self.assertEqual(repo_info.commit_id, 'abcd1234')
        self.assertTrue(os.path.exists(repo_info.local_path))
        
        # 验证Git操作
        mock_repo.clone_from.assert_called_once_with(
            'https://github.com/test/repo.git',
            os.path.join(self.clone_path, 'test_repo'),
            branch='main',
            depth=1
        )
    
    @patch('tools.sync.repo_handler.git.Repo')
    def test_update_repo(self, mock_repo):
        """测试更新仓库"""
        # 创建仓库目录
        repo_path = os.path.join(self.clone_path, 'test_repo')
        os.makedirs(repo_path, exist_ok=True)
        
        # 模拟Git操作
        mock_instance = MagicMock()
        mock_repo.return_value = mock_instance
        mock_instance.remotes.origin.pull.return_value = [MagicMock()]
        mock_instance.head.commit.hexsha = 'efgh5678'
        
        # 测试更新仓库
        success, repo_info = self.repo_handler.update_repo(
            'test_repo',
            'https://github.com/test/repo.git',
            'main'
        )
        
        # 验证结果
        self.assertTrue(success)
        self.assertEqual(repo_info.name, 'test_repo')
        self.assertEqual(repo_info.commit_id, 'efgh5678')
        
        # 验证Git操作
        mock_instance.git.checkout.assert_called_once_with('main')
        mock_instance.remotes.origin.pull.assert_called_once()


class TestRuleConverter(unittest.TestCase):
    """测试规则转换器"""
    
    def setUp(self):
        """测试前准备"""
        self.sigma_converter = SigmaConverter()
    
    def test_normalize_tags(self):
        """测试标签标准化"""
        # 测试标签标准化
        tags = ['Windows', 'attack.t1078', 'LATERAL movement', 'special-char!']
        normalized = self.sigma_converter.normalize_tags(tags)
        
        # 验证结果
        self.assertEqual(len(normalized), 4)
        self.assertIn('windows', normalized)
        self.assertIn('attackt1078', normalized)
        self.assertIn('lateral_movement', normalized)
        self.assertIn('special-char', normalized)
    
    def test_standardize_severity(self):
        """测试严重程度标准化"""
        # 测试各种严重程度值
        self.assertEqual(self.sigma_converter.standardize_severity('low'), 'low')
        self.assertEqual(self.sigma_converter.standardize_severity('l'), 'low')
        self.assertEqual(self.sigma_converter.standardize_severity('medium'), 'medium')
        self.assertEqual(self.sigma_converter.standardize_severity('med'), 'medium')
        self.assertEqual(self.sigma_converter.standardize_severity('high'), 'high')
        self.assertEqual(self.sigma_converter.standardize_severity('h'), 'high')
        self.assertEqual(self.sigma_converter.standardize_severity('critical'), 'critical')
        self.assertEqual(self.sigma_converter.standardize_severity('crit'), 'critical')
        self.assertEqual(self.sigma_converter.standardize_severity('unknown'), 'medium')  # 默认值
    
    def test_extract_mitre_tactics(self):
        """测试提取MITRE战术"""
        # 测试从Sigma标签中提取MITRE战术
        tags = ['attack.t1078', 'attack.t1021', 'windows']
        tactics = self.sigma_converter._extract_mitre_tactics(tags)
        
        # 验证结果
        self.assertEqual(len(tactics), 2)
        self.assertIn('TA1078', tactics)
        self.assertIn('TA1021', tactics)
    
    def test_convert_sigma_rule(self):
        """测试转换Sigma规则"""
        # 创建测试规则
        sigma_rule = {
            'title': '测试规则',
            'id': 'test-123',
            'description': '这是一个测试规则',
            'status': 'experimental',
            'author': '测试作者',
            'date': '2025-01-01',
            'modified': '2025-02-01',
            'level': 'high',
            'tags': ['windows', 'attack.t1078', 'lateral_movement'],
            'logsource': {
                'product': 'windows',
                'service': 'security'
            },
            'detection': {
                'selection': {
                    'EventID': 4624,
                    'LogonType': 3
                },
                'condition': 'selection'
            },
            'falsepositives': ['合法远程登录'],
            'references': ['https://example.com']
        }
        
        # 转换规则
        standard_rule = self.sigma_converter.convert(sigma_rule, 'test/path/rule.yml')
        
        # 验证结果
        self.assertEqual(standard_rule['name'], '测试规则')
        self.assertEqual(standard_rule['source']['id'], 'test-123')
        self.assertEqual(standard_rule['source']['type'], 'sigma')
        self.assertEqual(standard_rule['description'], '这是一个测试规则')
        self.assertEqual(standard_rule['author'], '测试作者')
        self.assertEqual(standard_rule['severity'], 'high')
        self.assertEqual(standard_rule['status'], 'experimental')
        self.assertEqual(standard_rule['created'], '2025-01-01')
        self.assertEqual(standard_rule['modified'], '2025-02-01')
        self.assertIn('windows', standard_rule['tags'])
        self.assertIn('lateral_movement', standard_rule['tags'])
        self.assertIn('windows', standard_rule['platforms'])
        self.assertEqual(len(standard_rule['falsepositives']), 1)
        self.assertEqual(len(standard_rule['references']), 1)
        self.assertIn('TA1078', standard_rule['mitre']['tactics'])


class TestSyncManager(unittest.TestCase):
    """测试同步管理器"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, 'sources.yml')
        
        # 创建测试配置文件
        with open(self.config_path, 'w') as f:
            f.write("""
sources:
  test_source:
    name: "Test Source"
    repo_url: "https://github.com/test/repo.git"
    branch: "main"
    paths:
      - "rules/test"
    format: "yaml"
    converter: "sigma_converter"
    enabled: true
    
global:
  clone_path: "./tmp/repos"
  timeout: 10
  concurrency: 1
            """)
        
        # 创建同步管理器
        self.sync_manager = SyncManager(self.config_path)
        
        # 修改基础目录为临时目录
        self.sync_manager.base_dir = Path(self.temp_dir)
        self.sync_manager.rules_dir = self.sync_manager.base_dir / "rules"
        self.sync_manager.temp_dir = self.sync_manager.base_dir / "tmp"
        
        # 创建目录
        os.makedirs(self.sync_manager.rules_dir, exist_ok=True)
        os.makedirs(self.sync_manager.temp_dir, exist_ok=True)
    
    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    def test_load_config(self):
        """测试加载配置"""
        # 验证配置加载
        config = self.sync_manager.config
        self.assertIn('sources', config)
        self.assertIn('test_source', config['sources'])
        self.assertIn('global', config)
        self.assertEqual(config['sources']['test_source']['name'], 'Test Source')
        self.assertEqual(config['global']['timeout'], 10)
    
    @patch('tools.sync.sync_manager.RepoHandler')
    @patch('tools.sync.sync_manager.ConverterFactory')
    def test_sync_source(self, mock_converter_factory, mock_repo_handler):
        """测试同步单个规则源"""
        # 模拟仓库处理器
        mock_repo_instance = MagicMock()
        self.sync_manager.repo_handler = mock_repo_instance
        
        # 模拟克隆仓库
        repo_info = MagicMock()
        repo_info.local_path = Path(os.path.join(self.temp_dir, 'tmp/repos/test_source'))
        repo_info.name = 'test_source'
        mock_repo_instance.clone_repo.return_value = (True, repo_info)
        
        # 创建测试规则目录
        rule_path = os.path.join(self.temp_dir, 'tmp/repos/test_source/rules/test')
        os.makedirs(rule_path, exist_ok=True)
        
        # 创建测试规则文件
        rule_file = os.path.join(rule_path, 'test_rule.yml')
        with open(rule_file, 'w') as f:
            f.write("title: Test Rule")
        
        # 模拟转换器
        mock_converter = MagicMock()
        mock_converter_factory.load_and_convert_rule.return_value = {
            'id': 'test-123',
            'name': 'Test Rule',
            'source': {'type': 'sigma'}
        }
        
        # 测试同步规则源
        source_config = self.sync_manager.config['sources']['test_source']
        result = self.sync_manager.sync_source('test_source', source_config)
        
        # 验证结果
        self.assertTrue(result['success'])
        self.assertEqual(result['total_rules'], 1)
        self.assertEqual(result['converted_rules'], 1)
        self.assertEqual(result['failed_rules'], 0)
        
        # 验证调用
        mock_repo_instance.clone_repo.assert_called_once()
        mock_converter_factory.load_and_convert_rule.assert_called_once()


if __name__ == '__main__':
    unittest.main()