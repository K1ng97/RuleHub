# RuleHub 规则格式参考

本文档详细说明RuleHub支持的规则格式以及规则转换机制。RuleHub旨在统一不同来源的安全检测规则，将它们转换为标准格式，便于管理和使用。

## 目录

- [标准规则格式](#标准规则格式)
  - [基本结构](#基本结构)
  - [字段说明](#字段说明)
  - [示例](#标准规则示例)
- [支持的源格式](#支持的源格式)
  - [Sigma格式](#sigma格式)
  - [Elastic格式](#elastic格式)
  - [Splunk格式](#splunk格式)
  - [MITRE格式](#mitre格式)
- [转换机制](#转换机制)
  - [转换流程](#转换流程)
  - [字段映射](#字段映射)
- [扩展支持](#扩展支持)
  - [添加新格式](#添加新格式)
  - [自定义转换器](#自定义转换器)
- [格式验证](#格式验证)
  - [验证规则](#验证规则)
  - [错误处理](#错误处理)

## 标准规则格式

### 基本结构

RuleHub使用JSON格式存储标准化后的规则。每个规则包含以下主要部分：

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

### 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| id | 字符串 | 是 | 规则唯一标识符 |
| name | 字符串 | 是 | 规则名称 |
| description | 字符串 | 否 | 规则详细描述 |
| source | 对象 | 是 | 规则来源信息 |
| source.type | 字符串 | 是 | 规则来源类型（如sigma, elastic, splunk等） |
| source.id | 字符串 | 否 | 原始规则ID |
| source.url | 字符串 | 否 | 原始规则URL |
| source.file_path | 字符串 | 否 | 原始规则文件路径 |
| tags | 字符串数组 | 否 | 规则标签列表 |
| author | 字符串 | 否 | 规则作者 |
| references | 字符串数组 | 否 | 参考链接列表 |
| severity | 字符串 | 否 | 规则严重程度（low, medium, high, critical） |
| type | 字符串 | 否 | 规则类型 |
| status | 字符串 | 否 | 规则状态（experimental, stable, deprecated） |
| created | 字符串 | 否 | 创建时间（ISO格式） |
| modified | 字符串 | 否 | 修改时间（ISO格式） |
| mitre | 对象 | 否 | MITRE ATT&CK映射 |
| mitre.tactics | 字符串数组 | 否 | MITRE战术ID列表 |
| mitre.techniques | 字符串数组 | 否 | MITRE技术ID列表 |
| detection | 对象 | 否 | 检测信息 |
| detection.query | 字符串 | 否 | 检测查询语句 |
| detection.condition | 字符串 | 否 | 检测条件 |
| detection.fields | 字符串数组 | 否 | 相关字段列表 |
| falsepositives | 字符串数组 | 否 | 可能的误报情况 |
| level | 字符串 | 否 | 风险等级（与severity相同） |
| rule_format | 字符串 | 否 | 规则格式，固定为"standard" |
| platforms | 字符串数组 | 否 | 适用平台列表 |
| data_sources | 字符串数组 | 否 | 数据源列表 |

### 标准规则示例

```json
{
    "id": "rule_bcd89e12",
    "name": "检测Windows PowerShell执行Base64编码命令",
    "description": "攻击者可能使用Base64编码来混淆PowerShell命令，避免被检测。",
    "source": {
        "type": "sigma",
        "id": "bc4a74de-5863-4471-9884-24cde15ee5f2",
        "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_base64_encoded_cmd.yml",
        "file_path": "rules/windows/powershell/powershell_base64_encoded_cmd.yml"
    },
    "tags": ["windows", "powershell", "obfuscation", "attack", "execution"],
    "author": "Sigma团队",
    "references": [
        "https://attack.mitre.org/techniques/T1059/001/",
        "https://blog.example.com/powershell-obfuscation"
    ],
    "severity": "medium",
    "type": "sigma",
    "status": "stable",
    "created": "2025-01-01T00:00:00Z",
    "modified": "2025-02-15T00:00:00Z",
    "mitre": {
        "tactics": ["TA0002"],
        "techniques": ["T1059.001"]
    },
    "detection": {
        "query": "process_name: 'powershell.exe' AND command_line: '*-enc*' OR command_line: '*-encodedcommand*'",
        "condition": "selection",
        "fields": ["process_name", "command_line", "user", "host"]
    },
    "falsepositives": [
        "管理脚本",
        "合法的PowerShell编码命令"
    ],
    "level": "medium",
    "rule_format": "standard",
    "platforms": ["windows"],
    "data_sources": ["process_creation", "command_line_logging"]
}
```

## 支持的源格式

RuleHub支持多种流行的规则格式，并自动将它们转换为标准格式。

### Sigma格式

[Sigma](https://github.com/SigmaHQ/sigma)是一种开源的通用SIEM规则格式。

**Sigma规则示例（YAML格式）：**

```yaml
title: Windows PowerShell Base64 Encoded Command
id: bc4a74de-5863-4471-9884-24cde15ee5f2
status: stable
description: 检测使用Base64编码的PowerShell命令执行
author: Sigma团队
date: 2025/01/01
modified: 2025/02/15
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://blog.example.com/powershell-obfuscation
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        process.name: 'powershell.exe'
        process.command_line|contains:
            - '-enc'
            - '-encodedcommand'
    condition: selection
falsepositives:
    - 管理脚本
    - 合法的PowerShell编码命令
level: medium
```

**字段映射：**

| Sigma字段 | 标准格式字段 |
|-----------|------------|
| title | name |
| id | source.id |
| status | status |
| description | description |
| author | author |
| date | created |
| modified | modified |
| references | references |
| tags | tags + mitre.tactics, mitre.techniques |
| logsource.product | platforms |
| detection | detection |
| falsepositives | falsepositives |
| level | severity, level |

### Elastic格式

Elastic Security提供的检测规则，通常使用JSON或NDJSON格式。

**Elastic规则示例（JSON格式）：**

```json
{
  "rule_id": "el4b87d1-9e3a-4f5b-b4d2-8761a7b2591d",
  "name": "PowerShell Base64 Encoded Command Execution",
  "description": "识别使用Base64编码的PowerShell命令，可能表示混淆尝试",
  "author": ["Elastic"],
  "references": [
    "https://attack.mitre.org/techniques/T1059/001/"
  ],
  "severity": "medium",
  "risk_score": 50,
  "rule_type": "query",
  "type": "eql",
  "created_at": "2025-01-01T00:00:00.000Z",
  "updated_at": "2025-02-15T00:00:00.000Z",
  "query": "process where process.name == \"powershell.exe\" and (process.args : \"*-enc*\" or process.args : \"*-encodedcommand*\")",
  "tags": [
    "Windows", "PowerShell", "Execution"
  ],
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0002",
        "name": "Execution",
        "reference": "https://attack.mitre.org/tactics/TA0002/"
      },
      "technique": [
        {
          "id": "T1059.001",
          "name": "Command and Scripting Interpreter: PowerShell",
          "reference": "https://attack.mitre.org/techniques/T1059/001/"
        }
      ]
    }
  ],
  "false_positives": [
    "管理脚本"
  ],
  "os_types": ["windows"]
}
```

**字段映射：**

| Elastic字段 | 标准格式字段 |
|------------|------------|
| rule_id | source.id |
| name | name |
| description | description |
| author | author |
| references | references |
| severity | severity |
| rule_type | type |
| created_at | created |
| updated_at | modified |
| query | detection.query |
| tags | tags |
| threat.tactic.id | mitre.tactics |
| threat.technique[].id | mitre.techniques |
| false_positives | falsepositives |
| os_types | platforms |

### Splunk格式

Splunk Security Content规则通常使用YAML格式。

**Splunk规则示例（YAML格式）：**

```yaml
name: PowerShell Base64 Encoded Commands
id: sp1e86c3-4a79-11eb-9c47-acde48001122
version: 1
date: '2025-01-01'
modified: '2025-02-15'
author: Splunk Threat Research
description: 检测潜在的混淆PowerShell Base64编码命令
type: detection
search: >-
  index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell/Operational 
  (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")
data_source:
  - Windows PowerShell Logs
tags:
  - PowerShell
  - Execution
  - Obfuscation
risk_score: 45
risk_severity: medium
mitre_attack_id:
  - T1059.001
  - TA0002
known_false_positives:
  - 管理脚本可能使用合法的编码命令
  - 自动化工具
fields:
  - CommandLine
  - User
  - Computer
status: production
asset_type: Windows
```

**字段映射：**

| Splunk字段 | 标准格式字段 |
|-----------|------------|
| name | name |
| id | source.id |
| description | description |
| author | author |
| date | created |
| modified | modified |
| type | type |
| search | detection.query |
| data_source | data_sources |
| tags | tags |
| risk_severity | severity |
| mitre_attack_id | mitre.tactics, mitre.techniques |
| known_false_positives | falsepositives |
| fields | detection.fields |
| status | status |
| asset_type | platforms |

### MITRE格式

MITRE Detection Lab规则使用JSON格式，与MITRE ATT&CK框架紧密集成。

**MITRE规则示例（JSON格式）：**

```json
{
  "id": "mt7a953e-8fc4-4ac1-a2e5-cdb7196969e9",
  "name": "PowerShell Base64 Encoded Command",
  "type": "detection",
  "description": "检测使用Base64编码的PowerShell命令执行，这可能是攻击者试图混淆恶意命令",
  "created": "2025-01-01T00:00:00Z",
  "modified": "2025-02-15T00:00:00Z",
  "platforms": ["windows"],
  "detection": {
    "condition": "powershell_process AND encoded_cmd",
    "definitions": {
      "powershell_process": {
        "process_name": "powershell.exe"
      },
      "encoded_cmd": {
        "command_line|contains": ["-enc", "-encodedcommand"]
      }
    }
  },
  "attack": {
    "tactics": ["execution"],
    "techniques": ["T1059.001"],
    "subtechniques": []
  },
  "data_sources": ["process_creation", "command_line_logging"],
  "severity": "medium",
  "false_positives": ["管理脚本", "自动化工具"],
  "references": [
    "https://attack.mitre.org/techniques/T1059/001/"
  ],
  "tags": ["powershell", "encoding", "obfuscation"]
}
```

**字段映射：**

| MITRE字段 | 标准格式字段 |
|----------|------------|
| id | source.id |
| name | name |
| type | type |
| description | description |
| created | created |
| modified | modified |
| platforms | platforms |
| detection | detection |
| attack.tactics | mitre.tactics |
| attack.techniques | mitre.techniques |
| data_sources | data_sources |
| severity | severity |
| false_positives | falsepositives |
| references | references |
| tags | tags |

## 转换机制

### 转换流程

RuleHub的规则转换过程包括以下步骤：

1. **读取原始规则**：从不同格式的文件中读取规则内容
2. **识别规则类型**：根据文件扩展名和内容识别规则类型
3. **选择转换器**：选择对应的规则转换器
4. **转换规则**：将原始规则转换为标准格式
5. **验证结果**：验证转换后的规则是否符合标准格式要求
6. **存储结果**：将转换后的规则保存为JSON文件

### 字段映射

转换过程中，系统会尝试将不同格式的字段映射到标准格式字段。对于特殊字段，会进行适当处理：

1. **MITRE映射**：从不同格式中提取MITRE战术和技术ID
2. **标签标准化**：统一标签格式，移除特殊字符，转换为小写
3. **严重程度标准化**：将不同系统的严重程度值映射到标准值（low, medium, high, critical）
4. **日期格式化**：统一日期格式为ISO 8601
5. **平台提取**：从标签或其他字段中提取适用平台信息

## 扩展支持

### 添加新格式

要添加对新规则格式的支持，需要以下步骤：

1. **创建转换器类**：在`tools/sync/rule_converter.py`中创建新的转换器类

```python
class NewFormatConverter(RuleConverter):
    def convert(self, rule_content: Dict, file_path: str) -> Dict:
        # 获取标准规则模板
        standard_rule = self.get_standard_rule_template()
        
        # 转换核心字段
        standard_rule["id"] = rule_content.get("id", self.generate_rule_id("newformat"))
        standard_rule["name"] = rule_content.get("title", "")
        # ... 其他字段映射
        
        return standard_rule
```

2. **注册转换器**：在`ConverterFactory`类中添加对新转换器的支持

```python
@staticmethod
def get_converter(source_type: str) -> RuleConverter:
    # ... 现有代码
    elif source_type.lower() == 'newformat':
        return NewFormatConverter()
    # ... 现有代码
```

3. **更新配置**：在`config/sources.yml`中添加新格式的配置

```yaml
sources:
  # ... 现有配置
  newformat:
    name: "New Format Rules"
    repo_url: "https://github.com/example/newformat.git"
    branch: "main"
    paths:
      - "rules"
    format: "json"  # 或其他格式
    converter: "newformat_converter"
    enabled: true
```

### 自定义转换器

您也可以实现自定义转换器来处理特殊格式的规则：

1. **扩展基类**：继承`RuleConverter`基类
2. **实现转换逻辑**：重写`convert`方法
3. **添加特殊处理**：根据需要添加特殊处理函数

例如，处理XML格式的规则：

```python
class XmlRuleConverter(RuleConverter):
    def convert(self, rule_content: Dict, file_path: str) -> Dict:
        standard_rule = self.get_standard_rule_template()
        
        # XML特殊处理逻辑
        # ...
        
        return standard_rule
        
    def parse_xml_rule(self, xml_content: str) -> Dict:
        # 解析XML内容
        # ...
        return parsed_rule
```

## 格式验证

### 验证规则

RuleHub使用JSON Schema验证转换后的规则是否符合标准格式：

```python
def validate_rule(rule: Dict) -> bool:
    """验证规则是否符合标准格式"""
    try:
        jsonschema.validate(instance=rule, schema=RULE_SCHEMA)
        return True
    except jsonschema.exceptions.ValidationError:
        return False
```

验证失败的规则将被记录但不会存储在索引中。

### 错误处理

转换过程中可能遇到的常见错误：

1. **必填字段缺失**：原始规则缺少必要字段
2. **格式不一致**：原始规则格式与预期不符
3. **日期格式错误**：日期字段格式不正确
4. **结构错误**：嵌套字段结构不正确

系统会记录这些错误，并尽可能应用合理的默认值或修复措施。