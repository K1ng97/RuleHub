#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
交互式向导模块
提供CLI交互式功能
"""

import os
import sys
import json
import logging
from typing import Dict, List, Any, Optional, Union, Tuple, Callable
from pathlib import Path
from datetime import datetime
import uuid

from prompt_toolkit import prompt
from prompt_toolkit.validation import Validator, ValidationError
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.shortcuts import radiolist_dialog, checkboxlist_dialog
from colorama import Fore, Style

from .utils.cli_utils import (
    print_success, print_error, print_warning, print_info, print_header,
    Colors, confirm_action
)

logger = logging.getLogger(__name__)

class NotEmptyValidator(Validator):
    """非空验证器"""
    
    def __init__(self, message: str = "此字段不能为空"):
        self.message = message
        super().__init__()
    
    def validate(self, document):
        if not document.text.strip():
            raise ValidationError(message=self.message)

class RuleWizard:
    """规则创建向导类"""
    
    def __init__(self, output_dir: Union[str, Path] = "rules"):
        """
        初始化规则创建向导
        
        Args:
            output_dir: 规则输出目录
        """
        self.output_dir = Path(output_dir)
        
        # 严重程度选项
        self.severity_options = [
            ("critical", "严重 (Critical)"),
            ("high", "高 (High)"),
            ("medium", "中 (Medium)"),
            ("low", "低 (Low)")
        ]
        
        # 平台选项
        self.platform_options = [
            ("windows", "Windows"),
            ("linux", "Linux"),
            ("macos", "macOS"),
            ("container", "容器"),
            ("cloud", "云平台"),
            ("network", "网络设备")
        ]
        
        # MITRE战术选项
        self.mitre_tactics = [
            ("initial_access", "初始访问 (Initial Access)"),
            ("execution", "执行 (Execution)"),
            ("persistence", "持久化 (Persistence)"),
            ("privilege_escalation", "权限提升 (Privilege Escalation)"),
            ("defense_evasion", "防御规避 (Defense Evasion)"),
            ("credential_access", "凭证访问 (Credential Access)"),
            ("discovery", "发现 (Discovery)"),
            ("lateral_movement", "横向移动 (Lateral Movement)"),
            ("collection", "收集 (Collection)"),
            ("command_and_control", "命令控制 (Command and Control)"),
            ("exfiltration", "渗出 (Exfiltration)"),
            ("impact", "影响 (Impact)")
        ]
    
    def create_rule(self) -> Dict:
        """
        创建新规则的交互式向导
        
        Returns:
            Dict: 创建的规则
        """
        print_header("规则创建向导")
        print_info("请按照提示填写规则信息，按Ctrl+C可以随时取消\n")
        
        try:
            # 生成规则ID
            rule_id = f"rule_{uuid.uuid4().hex[:8]}"
            
            # 收集基本信息
            name = prompt("规则名称: ", validator=NotEmptyValidator())
            description = prompt("规则描述: ", validator=NotEmptyValidator())
            
            # 选择严重程度
            print_info("\n请选择规则严重程度:")
            severity = self._prompt_choice(self.severity_options, "medium")
            
            # 输入标签
            tags_input = prompt("规则标签 (多个标签用逗号分隔): ")
            tags = [tag.strip() for tag in tags_input.split(",")] if tags_input else []
            
            # 选择平台
            print_info("\n请选择适用平台 (可多选):")
            platforms = self._prompt_multiple_choice(self.platform_options)
            
            # 选择MITRE战术
            print_info("\n请选择相关的MITRE ATT&CK战术 (可多选):")
            tactics = self._prompt_multiple_choice(self.mitre_tactics)
            
            # 输入MITRE技术
            techniques_input = prompt("MITRE ATT&CK技术 (例如: T1027,T1055): ")
            techniques = [tech.strip() for tech in techniques_input.split(",")] if techniques_input else []
            
            # 输入检测查询
            print_info("\n请输入检测查询 (可以是SQL、KQL或其他查询语言):")
            query = prompt("查询语句: ", validator=NotEmptyValidator())
            
            # 创建规则对象
            rule = {
                "id": rule_id,
                "name": name,
                "description": description,
                "source": {
                    "type": "custom",
                    "id": rule_id
                },
                "tags": tags,
                "severity": severity,
                "platforms": platforms,
                "mitre": {
                    "tactics": tactics,
                    "techniques": techniques
                },
                "created": datetime.now().isoformat(),
                "modified": datetime.now().isoformat(),
                "detection": {
                    "query": query
                }
            }
            
            # 确认保存
            print_info("\n规则信息收集完成，规则预览:")
            print(json.dumps(rule, indent=2, ensure_ascii=False))
            
            if confirm_action("是否保存此规则?", True):
                source_dir = self.output_dir / "custom"
                source_dir.mkdir(parents=True, exist_ok=True)
                
                output_file = source_dir / f"{rule_id}.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(rule, f, indent=2, ensure_ascii=False)
                    
                print_success(f"规则已保存到: {output_file}")
                return rule
            else:
                print_warning("已取消保存规则")
                return {}
                
        except KeyboardInterrupt:
            print_warning("\n已取消规则创建")
            return {}
    
    def _prompt_choice(self, options: List[Tuple[str, str]], default: str = None) -> str:
        """
        提示用户从选项中选择一个
        
        Args:
            options: 选项列表，每个选项是(值, 显示文本)的元组
            default: 默认选项值
            
        Returns:
            str: 选择的选项值
        """
        if not sys.stdout.isatty():
            # 非交互式环境，使用简单的提示
            print_info("可用选项:")
            for val, text in options:
                print(f"  - {val}: {text}")
            if default:
                choice = input(f"请选择 [{default}]: ") or default
            else:
                choice = input("请选择: ")
            return choice
            
        # 交互式环境，使用radiolist_dialog
        try:
            result = radiolist_dialog(
                title="请选择",
                values=[(val, text) for val, text in options],
                default=default
            ).run()
            return result or default
        except Exception:
            # 回退到简单选择
            print_info("请选择:")
            for i, (val, text) in enumerate(options, 1):
                print(f"{i}. {text} [{val}]")
            
            while True:
                try:
                    choice = input(f"请输入选项编号 [1-{len(options)}]: ")
                    if not choice and default:
                        return default
                    
                    idx = int(choice) - 1
                    if 0 <= idx < len(options):
                        return options[idx][0]
                    else:
                        print_error("无效的选择，请重试")
                except ValueError:
                    print_error("请输入有效的数字")
    
    def _prompt_multiple_choice(self, options: List[Tuple[str, str]]) -> List[str]:
        """
        提示用户从选项中选择多个
        
        Args:
            options: 选项列表，每个选项是(值, 显示文本)的元组
            
        Returns:
            List[str]: 选择的选项值列表
        """
        if not sys.stdout.isatty():
            # 非交互式环境，使用简单的提示
            print_info("可用选项 (多选，用逗号分隔):")
            for i, (val, text) in enumerate(options, 1):
                print(f"  {i}. {text} [{val}]")
            
            choices = input("请输入选项编号 (如 1,3,5): ")
            if not choices:
                return []
            
            try:
                indices = [int(c.strip()) - 1 for c in choices.split(",")]
                return [options[i][0] for i in indices if 0 <= i < len(options)]
            except (ValueError, IndexError):
                print_error("选择无效，使用空列表")
                return []
        
        # 交互式环境，使用checkboxlist_dialog
        try:
            result = checkboxlist_dialog(
                title="请选择 (可多选)",
                values=[(val, text) for val, text in options]
            ).run()
            return result or []
        except Exception:
            # 回退到简单选择
            print_info("请选择 (多选，用逗号分隔):")
            for i, (val, text) in enumerate(options, 1):
                print(f"{i}. {text} [{val}]")
            
            choices = input("请输入选项编号 (如 1,3,5): ")
            if not choices:
                return []
            
            try:
                indices = [int(c.strip()) - 1 for c in choices.split(",")]
                return [options[i][0] for i in indices if 0 <= i < len(options)]
            except (ValueError, IndexError):
                print_error("选择无效，使用空列表")
                return []

class VersionWizard:
    """版本创建向导类"""
    
    def __init__(self, versions_dir: Union[str, Path] = "versions"):
        """
        初始化版本创建向导
        
        Args:
            versions_dir: 版本目录
        """
        self.versions_dir = Path(versions_dir)
        self.versions_dir.mkdir(parents=True, exist_ok=True)
    
    def create_version(self) -> Dict:
        """
        创建新版本的交互式向导
        
        Returns:
            Dict: 创建的版本信息
        """
        print_header("版本创建向导")
        print_info("请按照提示填写版本信息，按Ctrl+C可以随时取消\n")
        
        try:
            # 获取当前已有版本
            current_version = self._get_latest_version()
            suggested_version = self._increment_version(current_version)
            
            # 输入版本号
            version = prompt(f"版本号 [{suggested_version}]: ")
            if not version:
                version = suggested_version
            
            # 输入发布说明
            print_info("\n请输入发布说明 (可以是多行文本，输入空行结束):")
            lines = []
            while True:
                line = input()
                if not line:
                    break
                lines.append(line)
            
            release_notes = "\n".join(lines)
            if not release_notes:
                release_notes = "常规更新"
            
            # 创建版本对象
            version_info = {
                "version": version,
                "release_date": datetime.now().isoformat(),
                "release_notes": release_notes,
                "changes": {
                    "added": [],
                    "changed": [],
                    "fixed": [],
                    "removed": []
                }
            }
            
            # 收集变更信息
            for change_type in ["added", "changed", "fixed", "removed"]:
                change_desc = {
                    "added": "新增功能",
                    "changed": "变更功能",
                    "fixed": "修复问题",
                    "removed": "移除功能"
                }
                
                print_info(f"\n请输入{change_desc[change_type]} (每行一项，输入空行结束):")
                changes = []
                while True:
                    change = input()
                    if not change:
                        break
                    changes.append(change)
                
                version_info["changes"][change_type] = changes
            
            # 确认保存
            print_info("\n版本信息收集完成，版本预览:")
            print(json.dumps(version_info, indent=2, ensure_ascii=False))
            
            if confirm_action("是否保存此版本?", True):
                output_file = self.versions_dir / f"v{version}.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(version_info, f, indent=2, ensure_ascii=False)
                    
                print_success(f"版本已保存到: {output_file}")
                
                # 更新latest.json
                latest_file = self.versions_dir / "latest.json"
                with open(latest_file, 'w', encoding='utf-8') as f:
                    json.dump({"latest": version}, f, indent=2, ensure_ascii=False)
                
                return version_info
            else:
                print_warning("已取消保存版本")
                return {}
                
        except KeyboardInterrupt:
            print_warning("\n已取消版本创建")
            return {}
            
    def _get_latest_version(self) -> str:
        """
        获取最新版本号
        
        Returns:
            str: 最新版本号
        """
        latest_file = self.versions_dir / "latest.json"
        if latest_file.exists():
            try:
                with open(latest_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return data.get("latest", "1.0.0")
            except Exception:
                return "1.0.0"
        return "1.0.0"
    
    def _increment_version(self, version: str) -> str:
        """
        增加版本号
        
        Args:
            version: 当前版本号
            
        Returns:
            str: 新版本号
        """
        try:
            parts = version.split(".")
            if len(parts) != 3:
                return "1.0.0"
                
            # 增加补丁版本号
            parts[2] = str(int(parts[2]) + 1)
            return ".".join(parts)
        except Exception:
            return "1.0.0"
    
    def generate_changelog(self, output_file: Union[str, Path] = "CHANGELOG.md") -> bool:
        """
        生成变更日志
        
        Args:
            output_file: 输出文件路径
            
        Returns:
            bool: 是否成功
        """
        try:
            versions = []
            
            # 获取所有版本文件
            version_files = list(self.versions_dir.glob("v*.json"))
            for file in version_files:
                try:
                    with open(file, 'r', encoding='utf-8') as f:
                        version_data = json.load(f)
                        versions.append(version_data)
                except Exception as e:
                    logger.warning(f"读取版本文件 {file} 失败: {e}")
            
            # 按版本号排序
            versions.sort(key=lambda v: [int(x) for x in v["version"].split(".")], reverse=True)
            
            # 生成变更日志
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# 变更日志\n\n")
                
                for v in versions:
                    version = v["version"]
                    date = v.get("release_date", "")
                    if date:
                        try:
                            date = datetime.fromisoformat(date.replace("Z", "+00:00")).strftime("%Y-%m-%d")
                        except:
                            pass
                    
                    f.write(f"## {version} ({date})\n\n")
                    
                    if v.get("release_notes"):
                        f.write(f"{v['release_notes']}\n\n")
                    
                    changes = v.get("changes", {})
                    
                    # 新增功能
                    if changes.get("added"):
                        f.write("### 新增\n\n")
                        for item in changes["added"]:
                            f.write(f"- {item}\n")
                        f.write("\n")
                    
                    # 变更功能
                    if changes.get("changed"):
                        f.write("### 变更\n\n")
                        for item in changes["changed"]:
                            f.write(f"- {item}\n")
                        f.write("\n")
                    
                    # 修复问题
                    if changes.get("fixed"):
                        f.write("### 修复\n\n")
                        for item in changes["fixed"]:
                            f.write(f"- {item}\n")
                        f.write("\n")
                    
                    # 移除功能
                    if changes.get("removed"):
                        f.write("### 移除\n\n")
                        for item in changes["removed"]:
                            f.write(f"- {item}\n")
                        f.write("\n")
                    
                    f.write("\n")
            
            print_success(f"变更日志已生成: {output_file}")
            return True
            
        except Exception as e:
            print_error(f"生成变更日志失败: {e}")
            logger.error(f"生成变更日志失败: {e}")
            return False