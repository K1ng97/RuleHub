#!/bin/bash

# 定义上游仓库的远程地址和分支
UPSTREAM_REPO="https://github.com/elastic/detection-rules.git"
UPSTREAM_BRANCH="main"
UPSTREAM_DIR="tree/main/rules"  # 上游仓库中的目录路径
LOCAL_DIR="../rules/opensource/elastic/"  # 你仓库中的目标目录路径

# 拉取上游仓库的最新数据
git fetch upstream

# 检查上游目录是否存在
if git ls-tree -d upstream/${UPSTREAM_BRANCH}:${UPSTREAM_DIR} > /dev/null 2>&1; then
    # 清空本地目录
    rm -rf ${LOCAL_DIR}/*
    # 拉取上游目录的内容到本地目录
    git checkout upstream/${UPSTREAM_BRANCH} -- ${UPSTREAM_DIR}/.
    mv ${UPSTREAM_DIR}/* ${LOCAL_DIR}/
    rmdir ${UPSTREAM_DIR}
else
    echo "Upstream directory does not exist."
fi

# 提交并推送本地仓库的更新
git add ${LOCAL_DIR}/
git commit -m "Sync ${UPSTREAM_DIR} from upstream"
git push origin main
