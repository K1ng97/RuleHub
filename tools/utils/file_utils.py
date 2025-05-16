#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件处理工具模块
提供基础的文件和目录操作函数
"""

import os
import json
import yaml
import shutil
import logging
from pathlib import Path
from datetime import datetime, date
from typing import Dict, List, Any, Union, Optional, TextIO

logger = logging.getLogger(__name__)

class DateTimeEncoder(json.JSONEncoder):
    """处理日期时间的JSON编码器"""
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)

def ensure_dir(directory: Union[str, Path]) -> Path:
    """
    确保目录存在，如果不存在则创建
    
    Args:
        directory: 目录路径
        
    Returns:
        Path: 目录路径对象
    """
    directory = Path(directory)
    if not directory.exists():
        directory.mkdir(parents=True)
        logger.debug(f"创建目录: {directory}")
    return directory

def read_yaml(file_path: Union[str, Path]) -> Dict:
    """
    读取YAML文件
    
    Args:
        file_path: YAML文件路径
        
    Returns:
        Dict: YAML文件内容
        
    Raises:
        FileNotFoundError: 文件不存在
        yaml.YAMLError: YAML解析错误
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except yaml.YAMLError as e:
        logger.error(f"YAML解析错误: {e}")
        raise

def write_yaml(data: Dict, file_path: Union[str, Path], create_dir: bool = True) -> None:
    """
    写入YAML文件
    
    Args:
        data: 要写入的数据
        file_path: 要写入的文件路径
        create_dir: 是否创建目录(如果不存在)
        
    Raises:
        IOError: 写入文件失败
    """
    file_path = Path(file_path)
    
    if create_dir:
        ensure_dir(file_path.parent)
    
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            yaml.dump(data, file, default_flow_style=False, allow_unicode=True)
        logger.debug(f"YAML文件写入成功: {file_path}")
    except IOError as e:
        logger.error(f"YAML文件写入失败: {e}")
        raise

def read_json(file_path: Union[str, Path]) -> Dict:
    """
    读取JSON文件
    
    Args:
        file_path: JSON文件路径
        
    Returns:
        Dict: JSON文件内容
        
    Raises:
        FileNotFoundError: 文件不存在
        json.JSONDecodeError: JSON解析错误
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        logger.error(f"JSON解析错误: {e}")
        raise

def write_json(data: Dict, file_path: Union[str, Path], indent: int = 2, create_dir: bool = True) -> None:
    """
    写入JSON文件
    
    Args:
        data: 要写入的数据
        file_path: 要写入的文件路径
        indent: 缩进空格数
        create_dir: 是否创建目录(如果不存在)
        
    Raises:
        IOError: 写入文件失败
    """
    file_path = Path(file_path)
    
    if create_dir:
        ensure_dir(file_path.parent)
    
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=indent, ensure_ascii=False, cls=DateTimeEncoder)
        logger.debug(f"JSON文件写入成功: {file_path}")
    except IOError as e:
        logger.error(f"JSON文件写入失败: {e}")
        raise

def list_files(directory: Union[str, Path], pattern: str = "*", recursive: bool = True) -> List[Path]:
    """
    列出目录中匹配模式的所有文件
    
    Args:
        directory: 目录路径
        pattern: 文件匹配模式，如 "*.yml"
        recursive: 是否递归搜索子目录
        
    Returns:
        List[Path]: 匹配的文件路径列表
    """
    directory = Path(directory)
    if not directory.exists():
        logger.warning(f"目录不存在: {directory}")
        return []
    
    # 处理花括号模式，如 "*.{yml,yaml}"
    if "{" in pattern and "}" in pattern:
        # 提取扩展名部分
        import re
        match = re.match(r".*\.\{(.*)\}", pattern)
        if match:
            extensions = match.group(1).split(",")
            result = []
            # 为每个扩展名单独执行glob
            for ext in extensions:
                if recursive:
                    result.extend(list(directory.glob(f"**/*.{ext}")))
                else:
                    result.extend(list(directory.glob(f"*.{ext}")))
            return result
    
    # 常规模式处理
    if recursive:
        return list(directory.glob(f"**/{pattern}"))
    else:
        return list(directory.glob(pattern))

def copy_file(src: Union[str, Path], dst: Union[str, Path], create_dst_dir: bool = True) -> None:
    """
    复制文件
    
    Args:
        src: 源文件路径
        dst: 目标文件路径
        create_dst_dir: 是否创建目标目录(如果不存在)
        
    Raises:
        FileNotFoundError: 源文件不存在
        IOError: 复制失败
    """
    src = Path(src)
    dst = Path(dst)
    
    if not src.exists():
        raise FileNotFoundError(f"源文件不存在: {src}")
    
    if create_dst_dir:
        ensure_dir(dst.parent)
    
    try:
        shutil.copy2(src, dst)
        logger.debug(f"文件复制成功: {src} -> {dst}")
    except IOError as e:
        logger.error(f"文件复制失败: {e}")
        raise

def remove_dir(directory: Union[str, Path], ignore_errors: bool = False) -> None:
    """
    删除目录及其内容
    
    Args:
        directory: 要删除的目录
        ignore_errors: 是否忽略错误
    """
    directory = Path(directory)
    if directory.exists():
        try:
            shutil.rmtree(directory, ignore_errors=ignore_errors)
            logger.debug(f"目录删除成功: {directory}")
        except Exception as e:
            logger.error(f"目录删除失败: {e}")
            if not ignore_errors:
                raise

def get_file_hash(file_path: Union[str, Path], algorithm: str = 'sha256') -> str:
    """
    计算文件哈希值
    
    Args:
        file_path: 文件路径
        algorithm: 哈希算法，支持'md5', 'sha1', 'sha256'等
        
    Returns:
        str: 文件哈希值
        
    Raises:
        FileNotFoundError: 文件不存在
        ValueError: 不支持的哈希算法
    """
    import hashlib
    
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    
    if algorithm not in hashlib.algorithms_available:
        raise ValueError(f"不支持的哈希算法: {algorithm}")
    
    hash_obj = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as file:
        # 分块读取，避免大文件内存问题
        for chunk in iter(lambda: file.read(4096), b''):
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()

def save_ndjson(data_list: List[Dict], file_path: Union[str, Path], create_dir: bool = True) -> None:
    """
    保存NDJSON格式文件（每行一个JSON对象）
    
    Args:
        data_list: 要保存的数据列表
        file_path: 文件路径
        create_dir: 是否创建目录(如果不存在)
    """
    file_path = Path(file_path)
    
    if create_dir:
        ensure_dir(file_path.parent)
    
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            for item in data_list:
                file.write(json.dumps(item, ensure_ascii=False) + '\n')
        logger.debug(f"NDJSON文件写入成功: {file_path}")
    except IOError as e:
        logger.error(f"NDJSON文件写入失败: {e}")
        raise

def read_ndjson(file_path: Union[str, Path]) -> List[Dict]:
    """
    读取NDJSON格式文件
    
    Args:
        file_path: 文件路径
        
    Returns:
        List[Dict]: NDJSON文件中的对象列表
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line:  # 跳过空行
                    results.append(json.loads(line))
        return results
    except json.JSONDecodeError as e:
        logger.error(f"NDJSON解析错误: {e}")
        raise

def get_file_modification_time(file_path: Union[str, Path]) -> float:
    """
    获取文件最后修改时间(UNIX时间戳)
    
    Args:
        file_path: 文件路径
        
    Returns:
        float: 最后修改时间的时间戳
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    
    return file_path.stat().st_mtime