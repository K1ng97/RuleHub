#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则同步管理器
负责协调整个同步过程，包括拉取规则、格式转换和索引生成
"""

import os
import sys
import time
import yaml
import json
import logging
import argparse
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
from concurrent.futures import ThreadPoolExecutor

from .repo_handler import RepoHandler
from .rule_converter import ConverterFactory
from ..utils.file_utils import (
    ensure_dir, read_yaml, write_json, list_files, 
    get_file_hash, save_ndjson
)
from ..indexing.indexer import RuleIndexer

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('rule_sync.log')
    ]
)
logger = logging.getLogger(__name__)


class SyncManager:
    """规则同步管理器类"""
    
    def __init__(self, config_path: Union[str, Path] = "config/sources.yml"):
        """
        初始化同步管理器
        
        Args:
            config_path: 配置文件路径
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        
        # 创建基础目录
        self.base_dir = Path(".")
        self.rules_dir = self.base_dir / "rules"
        self.temp_dir = self.base_dir / "tmp"
        
        ensure_dir(self.rules_dir)
        ensure_dir(self.temp_dir)
        
        # 获取全局配置
        global_config = self.config.get("global", {})
        clone_path = global_config.get("clone_path", "./tmp/repos")
        timeout = global_config.get("timeout", 600)
        
        # 创建仓库处理器
        self.repo_handler = RepoHandler(clone_path, timeout)
        
        # 统计信息
        self.stats = {
            "total_sources": 0,
            "successful_sources": 0,
            "failed_sources": 0,
            "total_rules": 0,
            "converted_rules": 0,
            "failed_rules": 0,
            "start_time": time.time(),
            "end_time": None,
            "duration": None,
            "details": {}
        }
        
    def _load_config(self) -> Dict:
        """
        加载配置文件
        
        Returns:
            Dict: 配置信息
        
        Raises:
            FileNotFoundError: 配置文件不存在
            yaml.YAMLError: YAML解析错误
        """
        try:
            return read_yaml(self.config_path)
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            sys.exit(1)
    
    def sync_all(self) -> Dict:
        """
        同步所有规则源
        
        Returns:
            Dict: 同步统计信息
        """
        logger.info("开始同步所有规则源")
        
        sources = self.config.get("sources", {})
        self.stats["total_sources"] = len(sources)
        
        # 获取并发数
        global_config = self.config.get("global", {})
        concurrency = global_config.get("concurrency", 2)
        
        # 使用线程池并发处理规则源
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            # 为每个规则源提交同步任务
            future_to_source = {
                executor.submit(self.sync_source, source_name, source_config): source_name
                for source_name, source_config in sources.items()
                if source_config.get("enabled", True)  # 只处理启用的规则源
            }
            
            # 等待所有任务完成
            for future in future_to_source:
                source_name = future_to_source[future]
                try:
                    result = future.result()
                    if result["success"]:
                        self.stats["successful_sources"] += 1
                    else:
                        self.stats["failed_sources"] += 1
                    
                    # 更新统计信息
                    self.stats["total_rules"] += result["total_rules"]
                    self.stats["converted_rules"] += result["converted_rules"]
                    self.stats["failed_rules"] += result["failed_rules"]
                    self.stats["details"][source_name] = result
                except Exception as e:
                    logger.error(f"同步源 {source_name} 时发生错误: {e}")
                    self.stats["failed_sources"] += 1
                    self.stats["details"][source_name] = {
                        "success": False,
                        "error": str(e),
                        "total_rules": 0,
                        "converted_rules": 0,
                        "failed_rules": 0
                    }
        
        # 生成索引
        try:
            logger.info("生成规则索引")
            indexer = RuleIndexer(self.rules_dir)
            index_stats = indexer.generate_index()
            self.stats["indexing"] = index_stats
        except Exception as e:
            logger.error(f"生成索引时发生错误: {e}")
            self.stats["indexing"] = {"success": False, "error": str(e)}
        
        # 更新统计信息
        self.stats["end_time"] = time.time()
        self.stats["duration"] = self.stats["end_time"] - self.stats["start_time"]
        
        # 保存统计信息
        try:
            stats_path = self.base_dir / "stats" / "sync_stats.json"
            ensure_dir(stats_path.parent)
            write_json(self.stats, stats_path)
        except Exception as e:
            logger.warning(f"保存统计信息失败: {e}")
        
        # 输出汇总信息
        logger.info(f"同步完成，共处理 {self.stats['total_sources']} 个规则源")
        logger.info(f"成功: {self.stats['successful_sources']}, 失败: {self.stats['failed_sources']}")
        logger.info(f"规则总数: {self.stats['total_rules']}, 转换成功: {self.stats['converted_rules']}, 转换失败: {self.stats['failed_rules']}")
        logger.info(f"总耗时: {self.stats['duration']:.2f} 秒")
        
        return self.stats
    
    def sync_source(self, source_name: str, source_config: Dict) -> Dict:
        """
        同步单个规则源
        
        Args:
            source_name: 规则源名称
            source_config: 规则源配置
            
        Returns:
            Dict: 同步结果统计
        """
        result = {
            "success": False,
            "start_time": time.time(),
            "end_time": None,
            "duration": None,
            "total_rules": 0,
            "converted_rules": 0,
            "failed_rules": 0,
            "error": None
        }
        
        try:
            logger.info(f"开始同步规则源: {source_name}")
            
            # 获取仓库信息
            repo_url = source_config.get("repo_url")
            branch = source_config.get("branch", "main")
            
            if not repo_url:
                raise ValueError(f"规则源 {source_name} 未提供仓库URL")
            
            # 克隆或更新仓库
            success, repo_info = self.repo_handler.clone_repo(source_name, repo_url, branch)
            
            if not success or not repo_info:
                raise RuntimeError(f"克隆规则源 {source_name} 仓库失败")
            
            # 获取规则路径和转换器
            rule_paths = [source_config.get("rule_path")]  # 适配新字段rule_path
            converter_type = source_config.get("converter", source_name)
            
            # 确保目标目录存在（同步前清空旧文件）
            output_dir = self.rules_dir / source_name
            # 清空目标目录
            if output_dir.exists():
                shutil.rmtree(output_dir)
            ensure_dir(output_dir)
            
            # 处理所有规则
            total_rules = 0
            converted_rules = 0
            failed_rules = 0
            
            for path in rule_paths:
                # 获取完整路径
                full_path = repo_info.local_path / path
                if not full_path.exists():
                    logger.warning(f"规则路径不存在: {full_path}")
                    continue
                
                # 获取规则文件格式（从配置或转换器推断）
                # 直接匹配所有规则文件
                pattern = "**/*"
                
                # 获取所有规则文件（过滤目录）
                rule_files = [f for f in list_files(full_path, pattern) if f.is_file()]
                total_rules += len(rule_files)
                
                # 转换每个规则
                for rule_file in rule_files:
                    try:
                        # 保留原始分类目录结构：获取规则文件相对路径并构造目标路径
                        relative_path = rule_file.relative_to(full_path)  # 基于rule_path路径计算相对路径
                        adjusted_relative = relative_path
                        output_path = output_dir / adjusted_relative
                        ensure_dir(output_path.parent)
                        shutil.copy2(rule_file, output_path)
                        converted_rules += 1
                        self.stats["total_rules"] += 1
                        
                    except Exception as e:
                        logger.error(f"处理规则 {rule_file} 时发生错误: {e}")
                        failed_rules += 1
            
            # 更新结果统计
            result["total_rules"] = total_rules
            result["converted_rules"] = converted_rules
            result["failed_rules"] = failed_rules
            result["success"] = True
            
            logger.info(f"规则源 {source_name} 同步完成")
            logger.info(f"总规则数: {total_rules}, 转换成功: {converted_rules}, 转换失败: {failed_rules}")
            
        except Exception as e:
            logger.error(f"同步规则源 {source_name} 失败: {e}")
            result["error"] = str(e)
        
        # 更新时间统计
        result["end_time"] = time.time()
        result["duration"] = result["end_time"] - result["start_time"]
        
        return result
    
    def clean_temp_files(self) -> None:
        """
        清理临时文件
        """
        logger.info("清理临时文件")
        try:
            # 清理仓库临时目录
            self.repo_handler.clean_all_repos()
            
            # 删除其他临时文件
            for path in list_files(self.temp_dir):
                try:
                    if path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        import shutil
                        shutil.rmtree(path)
                except Exception as e:
                    logger.warning(f"删除临时文件 {path} 失败: {e}")
                    
            logger.info("临时文件清理完成")
        except Exception as e:
            logger.error(f"清理临时文件时发生错误: {e}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="规则同步工具")
    parser.add_argument("--config", "-c", default="config/sources.yml", help="配置文件路径")
    parser.add_argument("--clean", action="store_true", help="同步后清理临时文件")
    parser.add_argument("--source", "-s", help="仅同步指定的规则源")
    args = parser.parse_args()
    
    try:
        # 创建同步管理器
        sync_manager = SyncManager(args.config)
        
        if args.source:
            # 仅同步指定的规则源
            sources = sync_manager.config.get("sources", {})
            if args.source not in sources:
                logger.error(f"规则源 {args.source} 不存在")
                sys.exit(1)
            
            source_config = sources[args.source]
            result = sync_manager.sync_source(args.source, source_config)
            
            # 生成索引
            indexer = RuleIndexer(sync_manager.rules_dir)
            indexer.generate_index()
            
            if not result["success"]:
                logger.error(f"同步规则源 {args.source} 失败: {result.get('error', '未知错误')}")
                sys.exit(1)
        else:
            # 同步所有规则源
            sync_manager.sync_all()
        
        # 清理临时文件
        if args.clean:
            sync_manager.clean_temp_files()
            
        logger.info("同步过程完成")
        
    except Exception as e:
        logger.error(f"同步过程中发生错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()