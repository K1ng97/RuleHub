# RuleHub 用户指南

## 简介

RuleHub是一个网络安全检测规则仓库系统，用于统一管理、转换和索引来自多个开源社区的安全检测规则。本指南将帮助您了解如何安装、配置和使用RuleHub系统。

## 功能特点

- 自动同步多个开源规则仓库
- 规则格式转换和标准化
- 规则索引和搜索
- 统一的规则管理接口
- 支持多种规则格式（Sigma、Elastic、Splunk等）
- MITRE ATT&CK映射和索引
- 版本管理和变更日志生成

## 系统要求

- Python 3.8+
- Git
- 足够的磁盘空间用于存储规则（推荐至少1GB）
- 网络连接（用于同步规则仓库）

## 安装

### 从源代码安装

1. 克隆仓库：

```bash
git clone https://github.com/yourusername/rulehub.git
cd rulehub
```

2. 安装依赖：

```bash
pip install -r requirements.txt
```

### Docker安装（可选）

如果您想使用Docker运行RuleHub，可以使用以下命令：

```bash
# 构建镜像
docker build -t rulehub .

# 运行容器
docker run -v $(pwd)/data:/app/data rulehub
```

或者使用docker-compose：

```bash
docker-compose up
```

## 配置

主要配置文件位于`config/sources.yml`，该文件定义了要同步的规则源。

### 配置文件示例

```yaml
sources:
  sigma:
    name: "Sigma Rules"
    description: "通用的开源SIEM规则格式"
    repo_url: "https://github.com/SigmaHQ/sigma.git"
    branch: "master"
    paths:
      - "rules/windows"
      - "rules/linux"
      - "rules/cloud"
      - "rules/network"
    format: "yaml"
    converter: "sigma_converter"
    update_interval: 86400  # 24小时，单位：秒
    enabled: true
    tags:
      - "sigma"
      - "open-source"
    priority: 1
    
  # 可以添加更多规则源...
  
global:
  default_output_format: "json"
  clone_path: "./tmp/repos"
  concurrency: 2
  timeout: 600
  log_level: "info"
```

### 添加新的规则源

您可以通过以下两种方式添加新的规则源：

1. 直接编辑配置文件
2. 使用命令行工具：

```bash
python3 rulehub.py repo add --name mysource --url https://github.com/example/rules.git --branch main --type custom --converter custom_converter --paths rules/detection --format json
```

## 基本使用

### 同步规则

```bash
# 同步所有规则源
python3 rulehub.py repo sync

# 同步特定规则源
python3 rulehub.py repo sync --source sigma

# 同步后清理临时文件
python3 rulehub.py repo sync --clean
```

### 生成索引

同步完成后，系统会自动生成索引。如果需要手动生成，可以使用：

```bash
python3 rulehub.py index generate
```

### 搜索规则

RuleHub提供了强大的搜索功能：

```bash
# 按标签搜索
python3 rulehub.py index search --tags windows,lateral_movement

# 按平台搜索
python3 rulehub.py index search --platforms windows,linux

# 按MITRE ATT&CK搜索
python3 rulehub.py index search --mitre-tactics TA0008 --mitre-techniques T1059

# 按严重程度搜索
python3 rulehub.py index search --severity high

# 按名称或描述搜索
python3 rulehub.py index search --name "PowerShell"
python3 rulehub.py index search --description "credential"

# 保存搜索结果
python3 rulehub.py index search --tags ransomware --output results.json
```

### 查看统计信息

```bash
# 查看系统的统计信息
python3 rulehub.py index stats

# 查看详细统计
python3 rulehub.py index stats --detailed
```

### 管理规则

```bash
# 列出规则
python3 rulehub.py rule list

# 查看规则详情
python3 rulehub.py rule show --id rule_12345678

# 创建新规则
python3 rulehub.py rule create

# 验证规则
python3 rulehub.py rule validate --id rule_12345678

# 测试规则
python3 rulehub.py rule test --id rule_12345678 --sample samples/test_data.json

# 更新规则
python3 rulehub.py rule update --id rule_12345678 --name "新名称" --severity high

# 删除规则
python3 rulehub.py rule delete --id rule_12345678
```

### 版本管理

```bash
# 列出版本
python3 rulehub.py version list

# 创建新版本
python3 rulehub.py version create

# 生成变更日志
python3 rulehub.py version changelog

# 查看版本详情
python3 rulehub.py version show --version 1.0.0
```

## 目录结构

安装完成后，系统会生成以下目录和文件：

- `rules/` - 存储所有转换后的规则
  - `sigma/` - Sigma 规则
  - `elastic/` - Elastic 规则
  - `splunk/` - Splunk 规则
  - `other/` - 其他规则

- `index/` - 存储索引文件
  - `rules_index.json` - 主索引文件
  - `rules_index_compact.json` - 精简索引
  - `tags_index.json` - 标签索引
  - `mitre_index.json` - MITRE ATT&CK 索引
  - `<source>_index.json` - 每个源的独立索引

- `stats/` - 存储统计信息
  - `sync_stats.json` - 同步统计

- `tmp/` - 存储临时文件
  - `repos/` - 克隆的仓库

## 常见问题解答

### 同步过程中出现网络错误

如果在同步过程中遇到网络错误，可以尝试以下解决方法：

1. 检查网络连接
2. 确认您可以访问配置的Git仓库
3. 如果使用代理，确保代理配置正确
4. 增加超时时间：编辑配置文件中的`timeout`值

### 规则验证失败

如果规则验证失败，可能是因为：

1. 规则格式不正确
2. 缺少必要的字段
3. 数据类型错误

请查看日志文件了解详细错误信息，并根据规则格式要求进行修正。

### 如何备份数据

建议定期备份以下目录：

1. `rules/` - 包含所有转换后的规则
2. `config/` - 包含配置文件
3. `versions/` - 包含版本信息

可以使用以下命令创建备份：

```bash
tar -czf rulehub_backup_$(date +%Y%m%d).tar.gz rules/ config/ versions/
```

## 获取帮助

如果您在使用过程中遇到任何问题，可以：

1. 查看详细的日志文件：`rulehub.log`、`rule_sync.log`和`validation.log`
2. 使用`--help`参数获取命令帮助
3. 查阅[开发者指南](developer_guide.md)了解更多技术细节
4. 提交Issue或贡献代码，请参考[贡献指南](contributing.md)

## 下一步

- 了解[规则格式](rule_format.md)
- 查看[API参考](api_reference.md)
- 探索[开发者指南](developer_guide.md)