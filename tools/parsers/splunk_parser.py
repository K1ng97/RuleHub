#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Splunk规则解析器
负责解析Splunk格式的规则文件，提取metadata信息
"""

import json
import yaml
import datetime
import logging
from pathlib import Path
from typing import Dict, Optional, Any

class SplunkParserConfig:
    """Splunk解析器配置类"""
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.rules_dir = self.project_root / Path('rules/splunk')
        self.output_path = self.project_root / Path('rules/splunk/splunk_metadata.json')


class SplunkParser:
    """Splunk规则解析器类"""
    def __init__(self, config: SplunkParserConfig):
        self.config = config
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(self.__class__.__name__)

    def parse_directory(self, dir_path: Path = None) -> list:
        """
        解析目录下所有Splunk规则文件，提取元数据并汇总

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

        # 遍历目录下所有.json文件（包括子目录）
        for file_path in dir_path.rglob('*.yml'):
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
        return metadata_list

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
        解析Splunk规则文件，提取metadata

        Args:
            file_path: 规则文件路径

        Returns:
            Dict: 包含metadata的字典，解析失败返回None
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_content = yaml.safe_load(f)

            date_value = rule_content.get('date', '')
            if isinstance(date_value, (datetime.datetime, datetime.date)):
                date_value = date_value.isoformat()
            metadata = {
                "id": rule_content.get('id', ''),
                "name": rule_content.get('name', ''),
                "description": rule_content.get('description', ''),
                "author": rule_content.get('author', ''),
                "date": date_value,
                "status": rule_content.get('status', ''),
                "tags": rule_content.get('tags', []),
                "logsource": rule_content.get('logsource', {})
            }
            return metadata
        except Exception as e:
            self.logger.error(f"解析Splunk规则文件 {file_path} 失败: {e}")
            return None

if __name__ == '__main__':
    # 配置日志
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    # 生产环境运行
    try:
        config = SplunkParserConfig()
    except Exception as e:
        logger.error(f"加载配置失败: {e}")
        sys.exit(1)
    parser = SplunkParser(config)
    # 解析目录下所有规则（使用配置中的路径或默认值）
    metadata_list = parser.parse_directory()
    logger.info(f"共解析 {len(metadata_list)} 条Splunk规则元数据")

    # 保存到JSON文件（使用配置中的路径或默认值）
    if parser.save_to_json(metadata_list):
        logger.info(f"元数据已保存至 {config.output_path}")
    else:
        logger.error("元数据保存失败")