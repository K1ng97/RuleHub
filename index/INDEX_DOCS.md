# 规则索引说明文档

## 一、索引文件概述
本项目索引系统生成以下类型的索引文件（存储于`index/`目录）：
- `rules_index.json`：主索引文件（完整规则信息）
- `rules_index_compact.json`：精简索引文件（仅含核心字段）
- `{source}_index.json`：源特定索引（如`splunk_index.json`、`elastic_index.json`等）
- `index_stats.json`：索引生成统计信息

## 二、索引文件结构
### 1. 主索引（rules_index.json）
```json
{
  "meta": {
    "version": "1.0.0",
    "generated_at": "2025-05-17T21:44:32.390112",
    "total_rules": 1764,
    "sources": {}
  },
  "rules": [
    {
      "id": "规则唯一ID",
      "name": "规则名称",
      "description": "规则描述",
      "source": {"type": "规则源类型（如splunk）"},
      "severity": "严重程度（如medium）",
      "tags": ["标签数组"],
      "platforms": ["平台数组"],
      "created": "创建时间",
      "modified": "修改时间",
      "rule_path": "规则元数据文件相对路径"
    }
  ]
}
```
- `meta`：索引元信息
  - `version`：索引版本
  - `generated_at`：生成时间（ISO 8601格式）
  - `total_rules`：总规则数
  - `sources`：各规则源统计（键为源类型，值含规则数和索引路径）
- `rules`：规则详情数组，包含从元数据文件加载的完整规则信息

### 2. 精简索引（rules_index_compact.json）
仅保留核心字段：
```json
{
  "meta": { /* 同主索引meta */ },
  "rules": [
    {
      "id": "规则唯一ID",
      "name": "规则名称",
      "severity": "严重程度",
      "rule_path": "规则元数据文件相对路径"
    }
  ]
}
```

### 3. 源特定索引（如splunk_index.json）
结构与主索引一致，但仅包含对应规则源（如splunk）的规则数据，`meta.source`字段标注源类型。

### 4. 统计信息（index_stats.json）
```json
{
  "total_rules": 1764,
  "total_sources": 3,
  "source_stats": {
    "splunk": {"name": "splunk", "rules_count": 588},
    "elastic": {"name": "elastic", "rules_count": 588},
    "sigma": {"name": "sigma", "rules_count": 588}
  },
  "by_source": {"splunk": 588, "elastic": 588, "sigma": 588},
  "by_severity": {"medium": 1500, "high": 264},
  "duration": 12.3
}
```

## 三、索引生成流程
1. **元数据文件扫描**：遍历`rules/`目录下所有`*_metadata.json`文件（如`splunk/splunk_metadata.json`）
2. **规则加载与清洗**：
   - 读取元数据文件中的规则列表
   - 处理非列表类型的`tags`字段（转换为"key:value"格式字符串数组）
3. **索引生成**：
   - 主索引：包含所有规则完整信息
   - 源索引：按规则源（splunk/elastic/sigma）拆分生成独立索引文件
   - 精简索引：从主索引提取核心字段
4. **格式验证**：使用`INDEX_SCHEMA`（定义于`tools/indexing/indexer.py`）验证索引结构
5. **统计信息生成**：记录规则总数、各源规则数、严重程度分布等

## 四、字段说明
| 字段名          | 类型       | 描述                                                                 |
|-----------------|------------|----------------------------------------------------------------------|
| id              | string     | 规则唯一标识符（UUID格式）                                           |
| name            | string     | 规则名称（如"Cisco IOS XE Implant Access"）                        |
| description     | string     | 规则详细描述（包含检测逻辑、威胁影响等）                             |
| source.type     | string     | 规则源类型（splunk/elastic/sigma）                                   |
| severity        | string     | 严重程度（medium/high/low）                                          |
| tags            | string[]   | 标签数组（含CVE编号、MITRE ATT&CK ID、安全域等）                     |
| rule_path       | string     | 规则元数据文件相对路径（如"splunk/splunk_metadata.json"）           |
| generated_at    | string     | 索引生成时间（ISO 8601格式，如"2025-05-17T21:44:32.390112"）        |

## 五、索引工具代码逻辑
核心类`RuleIndexer`（位于`tools/indexing/indexer.py`）实现以下功能：
- `generate_index()`：主入口方法，协调索引生成全流程
- `_load_all_rules()`：加载并清洗规则数据
- `_generate_main_index()`：生成主索引
- `_generate_compact_index()`：生成精简索引
- `_validate_index()`：使用`jsonschema`验证索引格式

> 注：本说明文档由索引生成工具自动维护，内容与`tools/indexing/indexer.py`逻辑及实际生成的索引文件严格一致。