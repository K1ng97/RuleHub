#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仓库处理模块
负责克隆和更新规则仓库
"""

import os
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
import shutil

import git
from git import Repo, GitCommandError

from ..utils.file_utils import ensure_dir, remove_dir

logger = logging.getLogger(__name__)

@dataclass
class RepoInfo:
    """仓库信息数据类"""
    name: str  # 仓库名称
    url: str  # 仓库URL
    branch: str  # 分支名
    local_path: Path  # 本地路径
    last_commit: Optional[str] = None  # 最后一次提交的哈希值
    last_updated: Optional[float] = None  # 最后一次更新时间戳


class RepoHandler:
    """
    仓库处理器类
    负责Git仓库的克隆和更新操作
    """
    
    def __init__(self, base_clone_path: Union[str, Path], timeout: int = 600):
        """
        初始化仓库处理器
        
        Args:
            base_clone_path: 仓库克隆的基础目录
            timeout: Git操作超时时间(秒)
        """
        self.base_clone_path = Path(base_clone_path)
        self.timeout = timeout
        ensure_dir(self.base_clone_path)
        self.repos: Dict[str, RepoInfo] = {}
        
    def clone_repo(self, name: str, repo_url: str, branch: str = "main") -> Tuple[bool, Optional[RepoInfo]]:
        """
        克隆仓库
        
        Args:
            name: 仓库名称
            repo_url: 仓库URL
            branch: 分支名
            
        Returns:
            Tuple[bool, Optional[RepoInfo]]: (是否成功, 仓库信息)
        """
        local_path = self.base_clone_path / name
        
        # 如果目录已存在，先移除
        if local_path.exists():
            logger.info(f"仓库本地目录已存在，正在移除: {local_path}")
            remove_dir(local_path, ignore_errors=True)
        
        ensure_dir(local_path)
        
        try:
            logger.info(f"正在克隆仓库 {name} 从 {repo_url} (分支: {branch})")
            repo = Repo.clone_from(
                repo_url, 
                local_path,
                branch=branch,
                depth=1,  # 浅克隆，只获取最近的提交
                env={"GIT_TERMINAL_PROMPT": "0"}  # 禁用身份验证提示
            )
            
            # 获取当前提交信息
            commit = repo.head.commit
            commit_hash = commit.hexsha
            
            repo_info = RepoInfo(
                name=name,
                url=repo_url,
                branch=branch,
                local_path=local_path,
                last_commit=commit_hash,
                last_updated=time.time()
            )
            
            self.repos[name] = repo_info
            logger.info(f"仓库 {name} 克隆成功，提交ID: {commit_hash[:8]}")
            return True, repo_info
            
        except GitCommandError as e:
            logger.error(f"克隆仓库 {name} 失败: {e}")
            # 清理失败的克隆
            if local_path.exists():
                remove_dir(local_path, ignore_errors=True)
            return False, None
        except Exception as e:
            logger.error(f"克隆仓库 {name} 过程中发生未知错误: {e}")
            # 清理失败的克隆
            if local_path.exists():
                remove_dir(local_path, ignore_errors=True)
            return False, None
    
    def update_repo(self, name: str) -> Tuple[bool, Optional[str], bool]:
        """
        更新仓库到最新状态
        
        Args:
            name: 仓库名称
            
        Returns:
            Tuple[bool, Optional[str], bool]: (是否成功, 最新提交哈希, 是否有更新)
        """
        if name not in self.repos:
            logger.error(f"仓库 {name} 不存在，无法更新")
            return False, None, False
        
        repo_info = self.repos[name]
        local_path = repo_info.local_path
        
        if not local_path.exists():
            logger.error(f"仓库本地目录不存在: {local_path}")
            return False, None, False
        
        try:
            logger.info(f"正在更新仓库 {name}")
            repo = Repo(local_path)
            
            # 保存当前提交哈希
            old_commit_hash = repo.head.commit.hexsha
            
            # 拉取最新代码
            origin = repo.remotes.origin
            origin.fetch()
            origin.pull()
            
            # 获取新的提交哈希
            new_commit_hash = repo.head.commit.hexsha
            has_updates = old_commit_hash != new_commit_hash
            
            # 更新仓库信息
            repo_info.last_commit = new_commit_hash
            repo_info.last_updated = time.time()
            
            if has_updates:
                logger.info(f"仓库 {name} 更新成功，有新的更改: {old_commit_hash[:8]} -> {new_commit_hash[:8]}")
            else:
                logger.info(f"仓库 {name} 已是最新状态: {new_commit_hash[:8]}")
                
            return True, new_commit_hash, has_updates
            
        except GitCommandError as e:
            logger.error(f"更新仓库 {name} 失败: {e}")
            return False, None, False
        except Exception as e:
            logger.error(f"更新仓库 {name} 过程中发生未知错误: {e}")
            return False, None, False
    
    def get_changed_files(self, name: str, old_commit: str, new_commit: str) -> List[str]:
        """
        获取两个提交之间的变更文件列表
        
        Args:
            name: 仓库名称
            old_commit: 旧的提交哈希
            new_commit: 新的提交哈希
            
        Returns:
            List[str]: 变更文件的相对路径列表
        """
        if name not in self.repos:
            logger.error(f"仓库 {name} 不存在")
            return []
        
        repo_info = self.repos[name]
        local_path = repo_info.local_path
        
        try:
            repo = Repo(local_path)
            diff_list = repo.git.diff("--name-only", old_commit, new_commit).split("\n")
            return [f for f in diff_list if f.strip()]
        except Exception as e:
            logger.error(f"获取仓库 {name} 变更文件失败: {e}")
            return []
    
    def get_repo_path(self, name: str) -> Optional[Path]:
        """
        获取仓库本地路径
        
        Args:
            name: 仓库名称
            
        Returns:
            Optional[Path]: 仓库本地路径，不存在则返回None
        """
        if name in self.repos:
            return self.repos[name].local_path
        return None
    
    def list_repos(self) -> List[RepoInfo]:
        """
        获取所有仓库信息
        
        Returns:
            List[RepoInfo]: 仓库信息列表
        """
        return list(self.repos.values())
    
    def clean_all_repos(self) -> None:
        """
        清理所有仓库的本地目录
        """
        logger.info(f"正在清理所有仓库本地目录: {self.base_clone_path}")
        for name, repo_info in self.repos.items():
            if repo_info.local_path.exists():
                logger.info(f"正在移除仓库目录: {repo_info.local_path}")
                remove_dir(repo_info.local_path, ignore_errors=True)
        
        # 清空仓库信息字典
        self.repos.clear()
        logger.info("所有仓库清理完成")