# RuleHub CLI 使用指南

RuleHub命令行工具提供了丰富的功能，让用户可以方便地管理和操作安全检测规则。本指南将帮助您了解和使用这些功能。

## 安装依赖

首先确保已安装所有依赖包：

```bash
pip install -r requirements.txt
```

## 命令结构

RuleHub CLI 使用分层的命令结构，格式为：

```
python rulehub.py <命令组> <命令> [选项]
```

主要命令组包括：

- `rule` - 规则管理
- `repo` - 仓库管理
- `index` - 索引管理
- `version` - 版本管理

## 规则管理命令

### 列出规则

```bash
# 列出所有规则
python rulehub.py rule list

# 按标签筛选
python rulehub.py rule list --tags windows,lateral_movement

# 按严重程度筛选
python rulehub.py rule list --severity high

# 按名称筛选
python rulehub.py rule list --name "检测Windows"

# 保存结果到文件
python rulehub.py rule list --output rules.json
```

### 显示规则详情

```bash
# 显示特定规则的详细信息
python rulehub.py rule show --id rule_12345678
```

### 创建规则

```bash
# 启动交互式规则创建向导
python rulehub.py rule create
```

向导将引导您完成规则创建过程，包括输入名称、描述、严重程度、标签、MITRE信息和检测查询等。

### 验证规则

```bash
# 验证特定规则
python rulehub.py rule validate --id rule_12345678

# 验证特定文件
python rulehub.py rule validate --file rules/custom/my_rule.json

# 验证目录中的所有规则
python rulehub.py rule validate --dir rules/custom
```

### 测试规则

```bash
# 使用样例数据测试规则
python rulehub.py rule test --id rule_12345678 --sample samples/test_data.json
```

### 更新规则

```bash
# 更新规则的各种属性
python rulehub.py rule update --id rule_12345678 --name "新名称" --severity high
```

### 删除规则

```bash
# 删除规则（需要确认）
python rulehub.py rule delete --id rule_12345678

# 强制删除规则（无需确认）
python rulehub.py rule delete --id rule_12345678 --force
```

## 仓库管理命令

### 列出规则仓库

```bash
# 列出所有规则源
python rulehub.py repo list

# 按名称排序
python rulehub.py repo list --sort name

# 保存结果到文件
python rulehub.py repo list --output repos.json
```

### 同步规则仓库

```bash
# 同步所有规则源
python rulehub.py repo sync

# 同步特定规则源
python rulehub.py repo sync --source sigma

# 同步后清理临时文件
python rulehub.py repo sync --clean
```

### 添加规则源

```bash
# 添加新的规则源
python rulehub.py repo add --name mysource --url https://github.com/example/rules.git
```

### 更新规则源

```bash
# 更新规则源配置
python rulehub.py repo update --name mysource --branch main --enable true
```

### 移除规则源

```bash
# 移除规则源
python rulehub.py repo remove --name mysource

# 移除规则源并删除相关规则文件
python rulehub.py repo remove --name mysource --delete-rules
```

## 索引管理命令

### 生成索引

```bash
# 生成索引
python rulehub.py index generate

# 强制重建索引
python rulehub.py index generate --force

# 显示详细输出
python rulehub.py index generate --verbose
```

### 搜索规则

```bash
# 基本搜索
python rulehub.py index search --tags lateral_movement

# 组合条件搜索
python rulehub.py index search --severity high --platform windows --tags mimikatz

# 使用MITRE信息搜索
python rulehub.py index search --mitre-tactics lateral_movement --mitre-techniques T1106

# 格式化输出
python rulehub.py index search --tags windows --format full

# 限制结果数量
python rulehub.py index search --tags windows --limit 10

# 保存结果到文件
python rulehub.py index search --tags windows --output search_results.json
```

### 显示统计信息

```bash
# 显示基本统计信息
python rulehub.py index stats

# 显示详细统计信息
python rulehub.py index stats --detailed

# 保存统计信息到文件
python rulehub.py index stats --output stats.json
```

## 版本管理命令

### 列出版本历史

```bash
# 列出所有版本
python rulehub.py version list

# 详细显示
python rulehub.py version list --format full

# 保存到文件
python rulehub.py version list --output versions.json
```

### 创建新版本

```bash
# 启动交互式版本创建向导
python rulehub.py version create

# 指定变更日志文件
python rulehub.py version create --changelog CHANGELOG.md
```

### 生成变更日志

```bash
# 生成变更日志
python rulehub.py version changelog

# 指定输出文件
python rulehub.py version changelog --output docs/CHANGELOG.md
```

### 显示版本详情

```bash
# 显示特定版本的详细信息
python rulehub.py version show --version 1.0.0
```

## 获取帮助

要获取任何命令的帮助信息，可以添加 `--help` 参数：

```bash
# 显示主程序帮助
python rulehub.py --help

# 显示命令组帮助
python rulehub.py rule --help

# 显示特定命令帮助
python rulehub.py rule create --help
```

## 彩色输出

RuleHub CLI 使用彩色输出使信息更易于阅读：

- 绿色: 成功信息
- 红色: 错误信息
- 黄色: 警告信息
- 蓝色: 提示信息

## 交互式功能

许多命令（如 `rule create` 和 `version create`）提供交互式向导，使用提示和选择列表引导您完成操作过程。这些交互式功能使用 `prompt_toolkit` 库提供更好的用户体验。

## 配置文件

大多数配置都存储在 `config/sources.yml` 文件中，特别是规则源配置。您可以手动编辑此文件，也可以使用 `repo` 命令组的命令进行管理。