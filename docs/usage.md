# RuleHub 使用指南

本文档提供了 RuleHub 网络安全检测规则仓库系统的使用指南。

## 安装依赖

在使用 RuleHub 之前，请确保已安装所有必要的依赖包：

```bash
pip install -r requirements.txt
```

## 基本命令

RuleHub 提供了一个名为 `rulehub.py` 的主要入口脚本，通过该脚本可以执行各种操作。使用方法如下：

```bash
python3 rulehub.py <命令> [选项]
```

## 同步规则

### 同步所有规则源

以下命令将同步 `config/sources.yml` 中配置的所有启用的规则源：

```bash
python3 rulehub.py sync
```

### 同步特定规则源

如果只需要同步特定的规则源，可以使用 `--source` 参数：

```bash
python3 rulehub.py sync --source sigma
```

### 同步并清理临时文件

同步完成后清理临时文件（如仓库克隆目录），可以添加 `--clean` 参数：

```bash
python3 rulehub.py sync --clean
```

## 生成索引

同步完成后，可以手动生成规则索引：

```bash
python3 rulehub.py index
```

注意：执行 `sync` 命令时已自动生成索引，此步骤一般不需要单独执行。

## 搜索规则

RuleHub 提供了强大的规则搜索功能，可以根据各种条件进行搜索：

### 按标签搜索

```bash
python3 rulehub.py search --tags windows,lateral_movement
```

### 按平台搜索

```bash
python3 rulehub.py search --platforms windows,linux
```

### 按 MITRE ATT&CK 搜索

```bash
python3 rulehub.py search --mitre-tactics TA0008 --mitre-techniques T1059
```

### 按严重程度搜索

```bash
python3 rulehub.py search --severity high
```

### 按名称或描述搜索

```bash
python3 rulehub.py search --name "PowerShell"
python3 rulehub.py search --description "credential"
```

### 保存搜索结果

将搜索结果保存到文件：

```bash
python3 rulehub.py search --tags ransomware --output results.json
```

## 查看统计信息

查看系统的统计信息：

```bash
python3 rulehub.py stats
```

查看特定统计：

```bash
# 查看同步统计
python3 rulehub.py stats --sync

# 查看索引统计
python3 rulehub.py stats --index
```

## 配置文件

RuleHub 的主要配置文件位于 `config/sources.yml`，该文件定义了要同步的规则源：

```yaml
sources:
  sigma:
    name: "Sigma Rules"
    repo_url: "https://github.com/SigmaHQ/sigma.git"
    branch: "master"
    paths:
      - "rules/windows"
      - "rules/linux"
    format: "yaml"
    converter: "sigma_converter"
    enabled: true
    
  # 可以添加更多规则源...
  
global:
  default_output_format: "json"
  clone_path: "./tmp/repos"
  concurrency: 2
```

## 输出目录结构

执行同步和索引后，系统会生成以下目录和文件：

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

## 预期输出结果

### 同步过程输出

执行同步命令后，终端将显示类似以下输出：

```
INFO - 开始同步所有规则源
INFO - 开始同步规则源: sigma
INFO - 仓库本地目录已存在，正在移除: ./tmp/repos/sigma
INFO - 正在克隆仓库 sigma 从 https://github.com/SigmaHQ/sigma.git (分支: master)
INFO - 仓库 sigma 克隆成功，提交ID: 7a9d3b21
INFO - 规则源 sigma 同步完成
INFO - 总规则数: 1357, 转换成功: 1342, 转换失败: 15
INFO - 开始同步规则源: elastic
INFO - 仓库本地目录已存在，正在移除: ./tmp/repos/elastic
...
INFO - 生成规则索引
INFO - 处理规则源: sigma
INFO - 处理规则源: elastic
...
INFO - 主索引已保存到: index/rules_index.json
INFO - 精简索引已保存到: index/rules_index_compact.json
INFO - 标签索引已保存到: index/tags_index.json
INFO - MITRE索引已保存到: index/mitre_index.json
INFO - 规则索引生成完成，共 2876 条规则，3 个规则源
INFO - 同步完成，共处理 3 个规则源
INFO - 成功: 3, 失败: 0
INFO - 规则总数: 2876, 转换成功: 2853, 转换失败: 23
INFO - 总耗时: 247.32 秒
```

### 统计信息输出

执行统计命令后，终端将显示类似以下输出：

```
=== 同步统计 ===
总规则源: 3
成功: 3, 失败: 0
总规则数: 2876
转换成功: 2853, 转换失败: 23
开始时间: 2025-05-16T10:15:23.456789
结束时间: 2025-05-16T10:19:30.987654
总耗时: 247.32 秒

规则源详情:
- sigma: 共 1357 条规则, 成功 1342, 失败 15
- elastic: 共 825 条规则, 成功 820, 失败 5
- splunk: 共 694 条规则, 成功 691, 失败 3

=== 索引统计 ===
总规则源: 3
总规则数: 2853
开始时间: 2025-05-16T10:18:45.123456
结束时间: 2025-05-16T10:19:30.654321
总耗时: 45.53 秒

规则源详情:
- sigma: 1342 条规则
- elastic: 820 条规则
- splunk: 691 条规则
```

## 常见问题解决

1. **克隆仓库失败**
   - 检查网络连接
   - 确认仓库 URL 是否正确
   - 查看防火墙设置

2. **规则转换失败**
   - 检查规则文件格式是否正确
   - 查看日志获取详细错误信息
   - 更新转换器代码以适应新的规则格式

3. **索引生成失败**
   - 确保规则目录中有转换后的规则
   - 检查文件权限
   - 查看日志获取详细错误信息

4. **搜索结果为空**
   - 确认索引文件已生成
   - 尝试使用更通用的搜索条件
   - 检查搜索条件拼写是否正确