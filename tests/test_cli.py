#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
命令行接口测试
"""

import os
import sys
import json
import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from io import StringIO

# 添加项目根目录到Python路径，以便导入模块
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入CLI模块
import rulehub
from tools.cli.commands import rule_commands, repo_commands, index_commands, version_commands
from tools.cli.utils import cli_utils


class TestCliUtils(unittest.TestCase):
    """测试CLI工具函数"""
    
    @patch('builtins.print')
    def test_print_functions(self, mock_print):
        """测试打印函数"""
        # 测试各种打印函数
        cli_utils.print_success("成功消息")
        cli_utils.print_error("错误消息")
        cli_utils.print_warning("警告消息")
        cli_utils.print_info("信息消息")
        cli_utils.print_header("标题")
        
        # 验证调用
        self.assertEqual(mock_print.call_count, 5)
    
    @patch('tools.cli.utils.cli_utils.input', return_value='y')
    def test_prompt_confirm_yes(self, mock_input):
        """测试确认提示-是"""
        result = cli_utils.prompt_confirm("确认操作?")
        self.assertTrue(result)
    
    @patch('tools.cli.utils.cli_utils.input', return_value='n')
    def test_prompt_confirm_no(self, mock_input):
        """测试确认提示-否"""
        result = cli_utils.prompt_confirm("确认操作?")
        self.assertFalse(result)
    
    @patch('tools.cli.utils.cli_utils.input', return_value='测试输入')
    def test_prompt_input(self, mock_input):
        """测试输入提示"""
        result = cli_utils.prompt_input("请输入:")
        self.assertEqual(result, '测试输入')
    
    @patch('tools.cli.utils.cli_utils.input', side_effect=['', '测试输入'])
    def test_prompt_input_required(self, mock_input):
        """测试必填输入提示"""
        result = cli_utils.prompt_input("请输入:", required=True)
        self.assertEqual(result, '测试输入')
        self.assertEqual(mock_input.call_count, 2)


class TestRuleCommands(unittest.TestCase):
    """测试规则管理命令"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.rules_dir = os.path.join(self.temp_dir, 'rules')
        os.makedirs(self.rules_dir, exist_ok=True)
        
        # 创建测试规则
        self.create_test_rules()
        
        # 创建参数对象
        self.args = MagicMock()
    
    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    def create_test_rules(self):
        """创建测试规则文件"""
        rule1 = {
            "id": "rule_12345678",
            "name": "检测PowerShell执行",
            "description": "检测PowerShell的执行",
            "severity": "medium",
            "tags": ["windows", "powershell", "execution"],
            "mitre": {
                "tactics": ["TA0002"],
                "techniques": ["T1059.001"]
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
            }
        }
        
        # 保存规则文件
        os.makedirs(os.path.join(self.rules_dir, 'sigma'), exist_ok=True)
        
        with open(os.path.join(self.rules_dir, 'sigma', 'rule_12345678.json'), 'w') as f:
            json.dump(rule1, f)
        
        with open(os.path.join(self.rules_dir, 'sigma', 'rule_87654321.json'), 'w') as f:
            json.dump(rule2, f)
    
    @patch('tools.cli.commands.rule_commands.print_info')
    @patch('tools.cli.commands.rule_commands.print_success')
    def test_list_rules(self, mock_print_success, mock_print_info):
        """测试列出规则命令"""
        # 设置参数
        self.args.id = None
        self.args.name = None
        self.args.tags = None
        self.args.severity = None
        self.args.source = None
        self.args.platform = None
        self.args.output = None
        
        # 替换规则目录
        with patch('tools.cli.commands.rule_commands.RULES_DIR', self.rules_dir):
            # 执行命令
            rule_commands.list_rules(self.args)
            
            # 验证输出
            mock_print_info.assert_called()
            mock_print_success.assert_called_once()
    
    @patch('tools.cli.commands.rule_commands.print_info')
    @patch('tools.cli.commands.rule_commands.print_error')
    def test_show_rule_not_found(self, mock_print_error, mock_print_info):
        """测试显示不存在的规则"""
        # 设置参数
        self.args.id = "nonexistent_rule"
        self.args.output = None
        
        # 替换规则目录
        with patch('tools.cli.commands.rule_commands.RULES_DIR', self.rules_dir):
            # 执行命令
            rule_commands.show_rule(self.args)
            
            # 验证输出
            mock_print_error.assert_called_once()
    
    @patch('tools.cli.commands.rule_commands.print_info')
    @patch('tools.cli.commands.rule_commands.print_success')
    def test_show_rule_found(self, mock_print_success, mock_print_info):
        """测试显示存在的规则"""
        # 设置参数
        self.args.id = "rule_12345678"
        self.args.output = None
        
        # 替换规则目录
        with patch('tools.cli.commands.rule_commands.RULES_DIR', self.rules_dir):
            # 执行命令
            rule_commands.show_rule(self.args)
            
            # 验证输出
            mock_print_success.assert_called_once()


class TestRepoCommands(unittest.TestCase):
    """测试仓库管理命令"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, 'sources.yml')
        
        # 创建测试配置文件
        with open(self.config_path, 'w') as f:
            f.write("""
sources:
  sigma:
    name: "Sigma Rules"
    repo_url: "https://github.com/SigmaHQ/sigma.git"
    branch: "master"
    paths:
      - "rules/windows"
    format: "yaml"
    converter: "sigma_converter"
    enabled: true
  elastic:
    name: "Elastic Rules"
    repo_url: "https://github.com/elastic/detection-rules.git"
    branch: "main"
    paths:
      - "rules"
    format: "ndjson"
    converter: "elastic_converter"
    enabled: false
    
global:
  clone_path: "./tmp/repos"
  timeout: 10
            """)
        
        # 创建参数对象
        self.args = MagicMock()
        self.args.config = self.config_path
    
    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    @patch('tools.cli.commands.repo_commands.print_info')
    @patch('tools.cli.commands.repo_commands.print_success')
    def test_list_repos(self, mock_print_success, mock_print_info):
        """测试列出仓库命令"""
        # 设置参数
        self.args.sort = None
        self.args.output = None
        
        # 执行命令
        repo_commands.list_repos(self.args)
        
        # 验证输出
        mock_print_info.assert_called()
        mock_print_success.assert_called_once()
    
    @patch('tools.cli.commands.repo_commands.SyncManager')
    @patch('tools.cli.commands.repo_commands.print_info')
    @patch('tools.cli.commands.repo_commands.print_success')
    def test_sync_repos(self, mock_print_success, mock_print_info, mock_sync_manager):
        """测试同步仓库命令"""
        # 设置参数
        self.args.source = None
        self.args.clean = False
        
        # 模拟同步管理器
        mock_instance = MagicMock()
        mock_sync_manager.return_value = mock_instance
        mock_instance.sync_all.return_value = {
            "total_sources": 2,
            "successful_sources": 2,
            "failed_sources": 0,
            "total_rules": 100,
            "converted_rules": 98,
            "failed_rules": 2
        }
        
        # 执行命令
        repo_commands.sync_repos(self.args)
        
        # 验证调用
        mock_sync_manager.assert_called_once_with(self.config_path)
        mock_instance.sync_all.assert_called_once()
        mock_print_success.assert_called_once()


class TestIndexCommands(unittest.TestCase):
    """测试索引管理命令"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.rules_dir = os.path.join(self.temp_dir, 'rules')
        self.index_dir = os.path.join(self.temp_dir, 'index')
        
        os.makedirs(self.rules_dir, exist_ok=True)
        os.makedirs(self.index_dir, exist_ok=True)
        
        # 创建参数对象
        self.args = MagicMock()
        self.args.rules_dir = self.rules_dir
        self.args.index_dir = self.index_dir
    
    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    @patch('tools.cli.commands.index_commands.RuleIndexer')
    @patch('tools.cli.commands.index_commands.print_info')
    @patch('tools.cli.commands.index_commands.print_success')
    def test_generate_index(self, mock_print_success, mock_print_info, mock_indexer):
        """测试生成索引命令"""
        # 设置参数
        self.args.force = False
        self.args.verbose = False
        
        # 模拟索引生成器
        mock_instance = MagicMock()
        mock_indexer.return_value = mock_instance
        mock_instance.generate_index.return_value = {
            "success": True,
            "total_rules": 100,
            "total_sources": 2,
            "duration": 5.5
        }
        
        # 执行命令
        index_commands.generate_index(self.args)
        
        # 验证调用
        mock_indexer.assert_called_once_with(self.rules_dir, self.index_dir)
        mock_instance.generate_index.assert_called_once()
        mock_print_success.assert_called_once()
    
    @patch('tools.cli.commands.index_commands.RuleIndexer')
    @patch('tools.cli.commands.index_commands.print_info')
    @patch('tools.cli.commands.index_commands.print_success')
    def test_search_rules(self, mock_print_success, mock_print_info, mock_indexer):
        """测试搜索规则命令"""
        # 设置参数
        self.args.id = None
        self.args.name = "PowerShell"
        self.args.description = None
        self.args.tags = None
        self.args.severity = None
        self.args.platform = None
        self.args.mitre_tactics = None
        self.args.mitre_techniques = None
        self.args.source = None
        self.args.limit = None
        self.args.format = None
        self.args.output = None
        
        # 模拟索引生成器
        mock_instance = MagicMock()
        mock_indexer.return_value = mock_instance
        mock_instance.search_rules.return_value = [
            {"id": "rule_12345678", "name": "检测PowerShell执行"}
        ]
        
        # 执行命令
        index_commands.search_rules(self.args)
        
        # 验证调用
        mock_indexer.assert_called_once_with(self.rules_dir, self.index_dir)
        mock_instance.search_rules.assert_called_once()
        mock_print_success.assert_called_once()


class TestVersionCommands(unittest.TestCase):
    """测试版本管理命令"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.versions_dir = os.path.join(self.temp_dir, 'versions')
        
        os.makedirs(self.versions_dir, exist_ok=True)
        
        # 创建参数对象
        self.args = MagicMock()
        self.args.dir = self.versions_dir
    
    def tearDown(self):
        """测试后清理"""
        shutil.rmtree(self.temp_dir)
    
    @patch('tools.cli.commands.version_commands.print_info')
    @patch('tools.cli.commands.version_commands.print_success')
    def test_list_versions_empty(self, mock_print_success, mock_print_info):
        """测试列出版本命令-空目录"""
        # 设置参数
        self.args.format = None
        self.args.output = None
        
        # 执行命令
        version_commands.list_versions(self.args)
        
        # 验证输出
        mock_print_info.assert_called()
    
    @patch('tools.cli.commands.version_commands.datetime')
    @patch('tools.cli.commands.version_commands.print_info')
    @patch('tools.cli.commands.version_commands.print_success')
    @patch('tools.cli.commands.version_commands.prompt_confirm', return_value=True)
    @patch('tools.cli.commands.version_commands.prompt_input', side_effect=["1.0.0", "初始版本"])
    def test_create_version(self, mock_prompt_input, mock_prompt_confirm, mock_print_success, mock_print_info, mock_datetime):
        """测试创建版本命令"""
        # 模拟日期
        mock_datetime.now.return_value.isoformat.return_value = "2025-05-16T12:00:00"
        
        # 设置参数
        self.args.changelog = os.path.join(self.temp_dir, 'CHANGELOG.md')
        
        # 执行命令
        version_commands.create_version(self.args)
        
        # 验证输出
        mock_print_success.assert_called_once()
        
        # 验证版本文件是否创建
        version_file = os.path.join(self.versions_dir, '1.0.0.json')
        self.assertTrue(os.path.exists(version_file))
        
        # 验证变更日志是否创建
        self.assertTrue(os.path.exists(self.args.changelog))


class TestMainScript(unittest.TestCase):
    """测试主脚本"""
    
    @patch('rulehub.setup_argparser')
    @patch('rulehub.registry')
    def test_main_version(self, mock_registry, mock_setup_argparser):
        """测试显示版本信息"""
        # 模拟参数解析器
        mock_parser = MagicMock()
        mock_setup_argparser.return_value = mock_parser
        
        # 模拟参数
        mock_args = MagicMock()
        mock_args.version = True
        mock_parser.parse_args.return_value = mock_args
        
        # 捕获stdout
        with patch('sys.stdout', new=StringIO()) as fake_out:
            # 执行main函数
            with self.assertRaises(SystemExit) as cm:
                rulehub.main()
            
            # 验证退出码
            self.assertEqual(cm.exception.code, 0)
            
            # 验证输出包含版本信息
            output = fake_out.getvalue()
            self.assertIn("RuleHub 版本", output)
    
    @patch('rulehub.setup_argparser')
    @patch('rulehub.registry')
    def test_main_no_command(self, mock_registry, mock_setup_argparser):
        """测试无命令时显示帮助"""
        # 模拟参数解析器
        mock_parser = MagicMock()
        mock_setup_argparser.return_value = mock_parser
        
        # 模拟参数
        mock_args = MagicMock()
        mock_args.version = False
        mock_args.command_group = None
        mock_parser.parse_args.return_value = mock_args
        
        # 执行main函数
        with self.assertRaises(SystemExit) as cm:
            rulehub.main()
        
        # 验证退出码
        self.assertEqual(cm.exception.code, 0)
        
        # 验证调用
        mock_parser.print_help.assert_called_once()


if __name__ == '__main__':
    unittest.main()