# RuleHub API参考

本文档提供RuleHub的命令行接口(CLI)和内部API的详细参考。这些接口可以用于脚本化操作、集成到其他系统或扩展RuleHub的功能。

## 目录

- [命令行接口(CLI)](#命令行接口cli)
  - [规则管理](#规则管理)
  - [仓库管理](#仓库管理)
  - [索引管理](#索引管理)
  - [版本管理](#版本管理)
  - [全局选项](#全局选项)
- [内部API](#内部api)
  - [同步模块](#同步模块)
  - [索引模块](#索引模块)
  - [验证模块](#验证模块)
  - [转换模块](#转换模块)
  - [辅助工具模块](#辅助工具模块)
- [数据结构](#数据结构)
  - [规则对象](#规则对象)
  - [索引对象](#索引对象)
  - [统计对象](#统计对象)
- [错误代码](#错误代码)
- [使用示例](#使用示例)
  - [脚本示例](#脚本示例)
  - [集成示例](#集成示例)

## 命令行接口(CLI)

RuleHub的CLI以`rulehub.py`为入口，使用命令组和子命令的结构。

### 规则管理

#### 列出规则

```
python3 rulehub.py rule list [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--id` | 按ID筛选规则 | 字符串 | - |
| `--name` | 按名称筛选规则 | 字符串 | - |
| `--tags` | 按标签筛选规则(逗号分隔) | 字符串 | - |
| `--severity` | 按严重程度筛选规则 | 字符串 | - |
| `--source` | 按规则源筛选规则 | 字符串 | - |
| `--platform` | 按平台筛选规则(逗号分隔) | 字符串 | - |
| `--output`, `-o` | 输出结果到文件 | 字符串 | - |

**示例：**

```bash
python3 rulehub.py rule list --tags windows,lateral_movement --severity high
```

#### 显示规则详情

```
python3 rulehub.py rule show --id RULE_ID [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--id` | 规则ID **(必填)** | 字符串 | - |
| `--output`, `-o` | 输出结果到文件 | 字符串 | - |

**示例：**

```bash
python3 rulehub.py rule show --id rule_12345678
```

#### 创建规则

```
python3 rulehub.py rule create [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--no-index` | 不更新索引 | 标志 | False |

**示例：**

```bash
python3 rulehub.py rule create
#### 验证规则

```
python3 rulehub.py rule validate [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--id` | 验证特定ID的规则 | 字符串 | - |
| `--file` | 验证特定文件 | 字符串 | - |
| `--dir` | 验证目录中的所有规则 | 字符串 | - |
| `--output`, `-o` | 输出验证报告到文件 | 字符串 | - |

**示例：**

```bash
python3 rulehub.py rule validate --dir rules/custom
```

#### 测试规则

```
python3 rulehub.py rule test --id RULE_ID [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--id` | 规则ID **(必填)** | 字符串 | - |
| `--sample` | 样例数据文件 | 字符串 | - |

**示例：**

```bash
python3 rulehub.py rule test --id rule_12345678 --sample samples/test_data.json
```

#### 更新规则

```
python3 rulehub.py rule update --id RULE_ID [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--id` | 规则ID **(必填)** | 字符串 | - |
| `--name` | 更新规则名称 | 字符串 | - |
| `--description` | 更新规则描述 | 字符串 | - |
| `--severity` | 更新严重程度 | 字符串 | - |
| `--tags` | 更新标签(逗号分隔) | 字符串 | - |
| `--platforms` | 更新平台(逗号分隔) | 字符串 | - |
| `--query` | 更新检测查询 | 字符串 | - |
| `--status` | 更新规则状态 | 字符串 | - |
| `--no-index` | 不更新索引 | 标志 | False |

**示例：**

```bash
python3 rulehub.py rule update --id rule_12345678 --name "新名称" --severity high
```

#### 删除规则

```
python3 rulehub.py rule delete --id RULE_ID [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--id` | 规则ID **(必填)** | 字符串 | - |
| `--force` | 强制删除，不提示确认 | 标志 | False |
| `--no-index` | 不更新索引 | 标志 | False |

**示例：**

```bash
python3 rulehub.py rule delete --id rule_12345678 --force
```

### 仓库管理

#### 列出规则仓库

```
python3 rulehub.py repo list [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--config`, `-c` | 配置文件路径 | 字符串 | config/sources.yml |
| `--sort` | 排序字段(name, type, status) | 字符串 | - |
| `--output`, `-o` | 输出结果到文件 | 字符串 | - |

**示例：**

```bash
python3 rulehub.py repo list --sort name
```

#### 同步规则仓库

```
python3 rulehub.py repo sync [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
#### 添加规则源

```
python3 rulehub.py repo add --name NAME --url URL [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--config`, `-c` | 配置文件路径 | 字符串 | config/sources.yml |
| `--name` | 规则源名称 **(必填)** | 字符串 | - |
| `--url` | 仓库URL **(必填)** | 字符串 | - |
| `--branch` | 分支名称 | 字符串 | - |
| `--type` | 规则类型 | 字符串 | - |
| `--converter` | 转换器名称 | 字符串 | - |
| `--format` | 规则格式 | 字符串 | - |
| `--paths` | 规则路径(逗号分隔) | 字符串 | - |
| `--force` | 强制覆盖现有配置 | 标志 | False |
| `--sync` | 添加后立即同步 | 标志 | False |

**示例：**

```bash
python3 rulehub.py repo add --name mysource --url https://github.com/example/rules.git --branch main --type custom --paths rules/detection --sync
```

#### 更新规则源

```
python3 rulehub.py repo update --name NAME [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--config`, `-c` | 配置文件路径 | 字符串 | config/sources.yml |
| `--name` | 规则源名称 **(必填)** | 字符串 | - |
| `--url` | 更新仓库URL | 字符串 | - |
| `--branch` | 更新分支名称 | 字符串 | - |
| `--type` | 更新规则类型 | 字符串 | - |
| `--converter` | 更新转换器名称 | 字符串 | - |
| `--format` | 更新规则格式 | 字符串 | - |
| `--paths` | 更新规则路径(逗号分隔) | 字符串 | - |
| `--enable` | 启用或禁用规则源 | 布尔值 | - |
| `--sync` | 更新后立即同步 | 标志 | False |

**示例：**

```bash
python3 rulehub.py repo update --name mysource --branch develop --enable true
```

#### 移除规则源

```
python3 rulehub.py repo remove --name NAME [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--config`, `-c` | 配置文件路径 | 字符串 | config/sources.yml |
| `--name` | 规则源名称 **(必填)** | 字符串 | - |
| `--force` | 强制删除，不提示确认 | 标志 | False |
| `--delete-rules` | 同时删除规则文件 | 标志 | False |

**示例：**

```bash
python3 rulehub.py repo remove --name mysource --delete-rules
```

### 索引管理

#### 生成索引

```
python3 rulehub.py index generate [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--rules-dir` | 规则目录 | 字符串 | rules |
| `--index-dir` | 索引目录 | 字符串 | index |
| `--force` | 强制重建索引 | 标志 | False |
| `--verbose`, `-v` | 显示详细输出 | 标志 | False |

**示例：**

```bash
python3 rulehub.py index generate --force --verbose
```

#### 搜索规则

```
python3 rulehub.py index search [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--id` | 按ID搜索 | 字符串 | - |
| `--name` | 按名称搜索 | 字符串 | - |
| `--description` | 按描述搜索 | 字符串 | - |
| `--tags` | 按标签搜索(逗号分隔) | 字符串 | - |
| `--severity` | 按严重程度搜索 | 字符串 | - |
| `--platform` | 按平台搜索(逗号分隔) | 字符串 | - |
| `--mitre-tactics` | 按MITRE战术搜索(逗号分隔) | 字符串 | - |
| `--mitre-techniques` | 按MITRE技术搜索(逗号分隔) | 字符串 | - |
| `--source` | 按规则源搜索 | 字符串 | - |
| `--limit` | 限制结果数量 | 整数 | - |
| `--format` | 输出格式(table, full, json) | 字符串 | - |
| `--output`, `-o` | 输出结果到文件 | 字符串 | - |

**示例：**

```bash
python3 rulehub.py index search --tags windows,mimikatz --severity high --limit 10 --format json
#### 显示统计信息

```
python3 rulehub.py index stats [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--detailed`, `-d` | 显示详细统计 | 标志 | False |
| `--output`, `-o` | 输出结果到文件 | 字符串 | - |

**示例：**

```bash
python3 rulehub.py index stats --detailed
```

### 版本管理

#### 列出版本历史

```
python3 rulehub.py version list [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--dir` | 版本目录 | 字符串 | versions |
| `--format` | 输出格式(table, full, json) | 字符串 | - |
| `--output`, `-o` | 输出结果到文件 | 字符串 | - |

**示例：**

```bash
python3 rulehub.py version list --format full
```

#### 创建新版本

```
python3 rulehub.py version create [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--dir` | 版本目录 | 字符串 | versions |
| `--changelog` | 生成变更日志文件 | 字符串 | CHANGELOG.md |

**示例：**

```bash
python3 rulehub.py version create --changelog docs/CHANGELOG.md
```

#### 生成变更日志

```
python3 rulehub.py version changelog [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--dir` | 版本目录 | 字符串 | versions |
| `--output`, `-o` | 输出文件路径 | 字符串 | CHANGELOG.md |

**示例：**

```bash
python3 rulehub.py version changelog --output docs/CHANGELOG.md
```

#### 显示版本详情

```
python3 rulehub.py version show --version VERSION [选项]
```

**选项：**

| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--dir` | 版本目录 | 字符串 | versions |
| `--version` | 版本号 **(必填)** | 字符串 | - |
| `--output`, `-o` | 输出结果到文件 | 字符串 | - |

**示例：**

```bash
python3 rulehub.py version show --version 1.0.0
```

### 全局选项

以下选项适用于所有命令：

#### RepoHandler类

```python
from tools.sync.repo_handler import RepoHandler

# 创建仓库处理器
repo_handler = RepoHandler(clone_path="./tmp/repos", timeout=600)

# 克隆仓库
success, repo_info = repo_handler.clone_repo(
    "sigma", 
    "https://github.com/SigmaHQ/sigma.git", 
    "master"
)

# 更新仓库
success, repo_info = repo_handler.update_repo(
    "sigma", 
    "https://github.com/SigmaHQ/sigma.git", 
    "master"
)

# 清理仓库
repo_handler.clean_repo("sigma")
repo_handler.clean_all_repos()
```

### 索引模块

#### RuleIndexer类

```python
from tools.indexing.indexer import RuleIndexer

# 创建索引生成器
indexer = RuleIndexer(rules_dir="rules", index_dir="index")

# 生成索引
stats = indexer.generate_index()

# 搜索规则
query = {
    "tags": ["windows", "mimikatz"],
    "severity": "high"
}
results = indexer.search_rules(query)
```

### 验证模块

#### Validator类

```python
from tools.validation.validator import Validator, ValidationLevel

# 创建验证器
validator = Validator()

# 验证单个规则
rule = {...}  # 规则内容
results = validator.validate_rule(rule)

# 验证文件
results = validator.validate_file("rules/custom/my_rule.json")

# 验证目录
results = validator.validate_directory("rules/custom")

# 检查验证结果
for result in results:
    if result.level == ValidationLevel.ERROR:
        print(f"错误: {result.message}")
    elif result.level == ValidationLevel.WARNING:
        print(f"警告: {result.message}")
```

#### DuplicateDetector类

```python
from tools.validation.duplicate_detector import DuplicateDetector

# 创建重复检测器
detector = DuplicateDetector(rules_dir="rules")

# 检测重复
duplicates = detector.detect_duplicates()

# 检查结果
for group in duplicates:
    print(f"发现 {len(group)} 个重复规则:")
    for rule_path in group:
        print(f"  - {rule_path}")
```

### 转换模块

#### ConverterFactory类

```python
from tools.sync.rule_converter import ConverterFactory

# 获取转换器
sigma_converter = ConverterFactory.get_converter("sigma")

# 加载并转换规则
rule = ConverterFactory.load_and_convert_rule(
    "path/to/rule.yml",
    "sigma"
)

# 手动转换规则内容
with open("path/to/rule.yml", "r") as f:
    content = yaml.safe_load(f)
    
standard_rule = sigma_converter.convert(content, "path/to/rule.yml")
```

### 辅助工具模块

#### 文件工具

```python
from tools.utils.file_utils import (
    ensure_dir, read_yaml, write_json, 
    list_files, get_file_hash
)

# 读取YAML文件
config = read_yaml("config/sources.yml")

# 写入JSON文件
write_json(data, "output.json")

# 列出文件
rule_files = list_files("rules/sigma", "*.yml")

# 计算文件哈希
file_hash = get_file_hash("rules/sigma/example.yml")

# 确保目录存在
ensure_dir("new_directory")
```

## 数据结构

### 规则对象

规则对象的标准格式如下：

```json
{
    "id": "rule_12345678",
    "name": "规则名称",
    "description": "规则描述",
    "source": {
        "type": "sigma",
        "id": "原始ID",
        "url": "原始URL",
        "file_path": "原始文件路径"
    },
    "tags": ["标签1", "标签2"],
    "author": "作者信息",
    "references": ["参考链接1", "参考链接2"],
    "severity": "high",
    "type": "规则类型",
    "status": "experimental",
    "created": "2025-01-01T00:00:00Z",
    "modified": "2025-01-15T00:00:00Z",
    "mitre": {
        "tactics": ["TA0001", "TA0002"],
        "techniques": ["T1001", "T1002"]
    },
    "detection": {
        "query": "检测查询",
        "condition": "检测条件",
        "fields": ["字段1", "字段2"]
    },
    "falsepositives": ["可能的误报1", "可能的误报2"],
    "level": "high",
    "rule_format": "standard",
    "platforms": ["windows", "linux"],
    "data_sources": ["数据源1", "数据源2"]
}
```

### 索引对象

索引对象包含所有规则的元数据：

```json
{
    "meta": {
        "version": "1.0.0",
        "generated_at": "2025-05-16T10:15:23.456789",
        "total_rules": 2853,
        "sources": {
            "sigma": {
                "count": 1342,
                "index_path": "sigma_index.json"
            },
            "elastic": {
                "count": 820,
                "index_path": "elastic_index.json"
            }
        }
    },
    "rules": [
        {
            "id": "rule_12345678",
            "name": "规则名称",
            "severity": "high",
            "rule_path": "rules/sigma/rule_12345678.json"
        }
    ]
}
```

### 统计对象

同步和索引操作会返回统计对象：

```json
{
    "total_sources": 3,
    "successful_sources": 3,
    "failed_sources": 0,
    "total_rules": 2876,
    "converted_rules": 2853,
    "failed_rules": 23,
    "start_time": "2025-05-16T10:15:23.456789",
    "end_time": "2025-05-16T10:19:30.987654",
    "duration": 247.53,
    "details": {
        "sigma": {
            "success": true,
            "total_rules": 1357,
            "converted_rules": 1342,
            "failed_rules": 15,
            "duration": 120.45
        }
    }
}
```

## 错误代码

RuleHub使用以下错误代码：

| 错误码 | 错误类型 | 说明 |
|-------|---------|------|
| 1 | `ImportError` | 导入模块失败 |
| 2 | `ConfigError` | 配置错误 |
| 3 | `RepoError` | 仓库操作错误 |
| 4 | `ConversionError` | 规则转换错误 |
| 5 | `ValidationError` | 规则验证错误 |
| 6 | `IndexError` | 索引操作错误 |
| 7 | `FileError` | 文件操作错误 |
| 8 | `CommandError` | 命令执行错误 |

## 使用示例

### 脚本示例

#### 定期同步脚本

```python
#!/usr/bin/env python3
# sync_rules.py

import sys
import logging
from tools.sync.sync_manager import SyncManager
from tools.cli.utils.cli_utils import print_success, print_error

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='sync.log'
)

def main():
    try:
        # 创建同步管理器
        sync_manager = SyncManager()
        
        # 同步所有规则源
        stats = sync_manager.sync_all()
        
        # 清理临时文件
        sync_manager.clean_temp_files()
        
        # 输出统计信息
        print_success(f"同步完成，共处理 {stats['total_rules']} 条规则，成功转换 {stats['converted_rules']} 条")
        
        return 0
    except Exception as e:
        print_error(f"同步失败: {e}")
        logging.error(f"同步失败: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

### 集成示例

#### 将RuleHub集成到安全平台

```python
#!/usr/bin/env python3
# security_platform_integration.py

import json
import requests
from tools.indexing.indexer import RuleIndexer

# 配置
RULEHUB_DIR = "/path/to/rulehub"
API_ENDPOINT = "https://security-platform.example.com/api/rules"
API_KEY = "your_api_key"

# 创建索引器
indexer = RuleIndexer(f"{RULEHUB_DIR}/rules", f"{RULEHUB_DIR}/index")

# 搜索高风险规则
query = {
    "severity": "high",
    "platforms": ["windows"]
}
high_risk_rules = indexer.search_rules(query)

# 转换为平台格式
platform_rules = []
for rule in high_risk_rules:
    platform_rule = {
        "name": rule["name"],
        "description": rule["description"],
        "query": rule.get("detection", {}).get("query", ""),
        "severity": rule["severity"],
        "tags": rule["tags"],
        "source": "RuleHub"
    }
    platform_rules.append(platform_rule)

# 发送到安全平台
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {API_KEY}"
}

response = requests.post(
    API_ENDPOINT,
    headers=headers,
    data=json.dumps(platform_rules)
)

if response.status_code == 200:
    print(f"成功集成 {len(platform_rules)} 条规则到安全平台")
else:
    print(f"集成失败: {response.status_code} - {response.text}")
```
| 选项 | 说明 | 类型 | 默认值 |
|------|------|------|-------|
| `--help`, `-h` | 显示帮助信息 | 标志 | - |
| `--version`, `-v` | 显示版本信息 | 标志 | - |

## 内部API

RuleHub的内部API可以用于扩展功能或集成到其他系统中。以下是主要模块的核心API参考。

### 同步模块

#### SyncManager类

```python
from tools.sync.sync_manager import SyncManager

# 创建同步管理器
sync_manager = SyncManager(config_path="config/sources.yml")

# 同步所有规则源
stats = sync_manager.sync_all()

# 同步特定规则源
source_config = {...}  # 规则源配置
result = sync_manager.sync_source("sigma", source_config)

# 清理临时文件
sync_manager.clean_temp_files()
```
```
| `--config`, `-c` | 配置文件路径 | 字符串 | config/sources.yml |
| `--source`, `-s` | 仅同步指定的规则源 | 字符串 | - |
| `--clean` | 同步后清理临时文件 | 标志 | False |

**示例：**

```bash
python3 rulehub.py repo sync --source sigma --clean
```