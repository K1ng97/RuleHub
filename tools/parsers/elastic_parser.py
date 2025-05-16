#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Elastic规则解析器
负责解析Elastic格式的规则文件，提取metadata信息
"""

import tomlkit as toml
import json
import datetime
import logging
from pathlib import Path
from typing import Dict, Optional, Any

class ElasticParserConfig:
    """Elastic解析器配置类"""
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.rules_dir = self.project_root / Path('rules/elastic')
        self.output_path = self.project_root / Path('rules/elastic/elastic_metadata.json')


class ElasticParser:
    """Elastic规则解析器类"""
    def __init__(self, config: ElasticParserConfig):
        self.config = config
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(self.__class__.__name__)

    def parse_directory(self, dir_path: Path = None) -> list:
        """
        解析目录下所有Elastic规则文件，提取元数据并汇总

        Args:
            dir_path: 规则目录路径

        Returns:
            list: 所有规则文件的元数据列表
        """
        dir_path = dir_path or self.config.rules_dir
        metadata_list = []
        total_files = 0  # 总规则文件数
        all_files = []  # 所有处理的文件路径
        success_files = []  # 成功解析的文件路径

        # 遍历目录下所有.toml文件（包括子目录）
        for file_path in dir_path.rglob('*.toml'):
            if file_path.is_file():
                total_files += 1
                all_files.append(file_path)
                meta = self.parse(file_path)
                if meta:
                    # 添加文件路径信息
                    meta['file_path'] = str(file_path.relative_to(dir_path))
                    metadata_list.append(meta)
                    success_files.append(file_path)

        # 检查解析数量是否一致
        failed_count = total_files - len(metadata_list)
        if len(metadata_list) != total_files:
            failed_files = [str(fp) for fp in all_files if fp not in success_files]
            self.logger.warning(f"总规则文件数：{total_files}，解析成功：{len(metadata_list)}，解析失败：{failed_count}。以下文件解析失败：{failed_files}")
        else:
            self.logger.info(f"总规则文件数：{total_files}，解析成功：{total_files}，解析失败：0。所有规则文件解析成功。")
        return metadata_list, total_files

    def save_to_json(self, metadata_list: list, output_path: Path = None) -> bool:
        """
        将元数据列表保存为JSON文件

        Args:
            metadata_list: 元数据列表
            output_path: 输出文件路径

        Returns:
            bool: 保存成功状态
        """
        output_path = output_path or self.config.output_path
        try:
            # 确保输出目录存在
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(metadata_list, f, indent=2, ensure_ascii=False, default=lambda obj: obj.isoformat() if isinstance(obj, (datetime.datetime, datetime.date)) else str(obj))
            return True
        except Exception as e:
            self.logger.error(f"保存元数据到 {output_path} 失败: {e}")
            return False

    def parse(self, file_path: Path) -> Optional[Dict]:
        """
        解析Elastic规则文件，提取metadata

        Args:
            file_path: 规则文件路径

        Returns:
            Dict: 包含metadata的字典，解析失败返回None
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                try:
                    rule_content = toml.parse(content)
                except toml.exceptions.ParseError as e:
                    # 尝试修复未闭合字符串（简单追加闭合引号）
                    if 'Unterminated string' in str(e) or 'Unbalanced quotes' in str(e):
                        content += '"'
                        rule_content = toml.parse(content)
                    else:
                        raise

            metadata_section = rule_content.get('metadata', {})
            rule_section = rule_content.get('rule', {})

            # 处理日期字段
            # 增强日期字段解析（支持字符串格式日期）
            creation_date = metadata_section.get('creation_date', '')
            if isinstance(creation_date, (datetime.datetime, datetime.date)):
                creation_date = creation_date.isoformat()
            elif isinstance(creation_date, str) and '/' in creation_date:
                try:
                    creation_date = datetime.datetime.strptime(creation_date, '%Y/%m/%d').isoformat()
                except ValueError:
                    pass  # 保留原始字符串

            updated_date = metadata_section.get('updated_date', '')
            if isinstance(updated_date, (datetime.datetime, datetime.date)):
                updated_date = updated_date.isoformat()
            elif isinstance(updated_date, str) and '/' in updated_date:
                try:
                    updated_date = datetime.datetime.strptime(updated_date, '%Y/%m/%d').isoformat()
                except ValueError:
                    pass  # 保留原始字符串

            deprecation_date = metadata_section.get('deprecation_date', '')
            if isinstance(deprecation_date, (datetime.datetime, datetime.date)):
                deprecation_date = deprecation_date.isoformat()
            elif isinstance(deprecation_date, str) and '/' in deprecation_date:
                try:
                    deprecation_date = datetime.datetime.strptime(deprecation_date, '%Y/%m/%d').isoformat()
                except ValueError:
                    pass  # 保留原始字符串

            # 增强字段类型检查和空值处理
            try:
                # 增强字段存在性检查和类型安全处理
                metadata = {
                    "id": rule_section.get('rule_id', ''),
                    "name": rule_section.get('name', ''),
                    "description": rule_section.get('description', ''),
                    "author": [rule_section.get('author', '')] if isinstance(rule_section.get('author'), str) and rule_section.get('author') else rule_section.get('author', []),  # 处理空值和字符串转列表
                    "creation_date": creation_date,
                    "maturity": metadata_section.get('maturity', ''),
                    "min_stack_version": metadata_section.get('min_stack_version', ''),
                    "updated_date": updated_date,
                    "deprecation_date": deprecation_date,
                    "status": rule_section.get('status', ''),
                    "tags": rule_section.get('tags', []) if isinstance(rule_section.get('tags'), list) else [],  # 确保tags为列表
                    "logsource": rule_section.get('logsource', {}) if isinstance(rule_section.get('logsource', {}), dict) else {},  # 确保logsource为字典并处理空值  # 确保logsource为字典
                    "risk_score": rule_section.get('risk_score', '') if rule_section.get('risk_score') is not None else '',  # 处理risk_score空值
                    "severity": rule_section.get('severity', '') if rule_section.get('severity') is not None else '',  # 处理severity空值
                    "index": rule_section.get('index', []) if isinstance(rule_section.get('index'), list) else [],  # 确保index为列表
                    "language": rule_section.get('language', ''),
                    "license": rule_section.get('license', ''),
                    "type": rule_section.get('type', '')
                }
            except Exception as e:
                self.logger.error(f"字段提取失败（文件：{file_path}）: 具体字段={str(e)}，当前rule_section={rule_section}")
                return None
            return metadata
        except toml.TomlDecodeError as e:
            self.logger.error(f"解析Elastic规则文件 {file_path} 失败（TOML语法错误）: 行{e.lineno}, 列{e.colno} - {e.msg}\n请检查文件中的字符串是否使用双引号闭合，特殊字符是否转义（如\"）")
            return None
        except (IndexError, KeyError) as e:  # 同时捕获索引越界和键不存在错误
            self.logger.error(f"解析Elastic规则文件 {file_path} 失败（索引越界）: {e}")
            return None
        except Exception as e:
            self.logger.error(f"解析Elastic规则文件 {file_path} 失败（未知错误）: {e}")
            return None

if __name__ == '__main__':
    # 配置日志
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    # 生产环境运行
    try:
        config = ElasticParserConfig()
    except Exception as e:
        logger.error(f"加载配置失败: {e}")
        sys.exit(1)
    parser = ElasticParser(config)
    # 解析目录下所有规则（使用配置中的路径或默认值）
    metadata_list, total_files = parser.parse_directory()
    failed_count = total_files - len(metadata_list)
    logger.info(f"总规则文件数：{total_files}，解析成功：{len(metadata_list)}，解析失败：{failed_count}")

    # 保存到JSON文件（使用配置中的路径或默认值）
    if parser.save_to_json(metadata_list):
        logger.info(f"元数据已保存至 {config.output_path}")
    else:
        logger.error("元数据保存失败")