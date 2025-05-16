# RuleHub 开发者指南

## 简介

本指南面向希望了解RuleHub内部工作原理、进行二次开发或扩展功能的开发者。RuleHub是一个模块化设计的网络安全检测规则仓库系统，通过了解其架构和关键组件，您可以更有效地扩展和定制系统。

## 系统架构

RuleHub采用模块化设计，主要由以下几个核心组件组成：

1. **命令行接口(CLI)** - 提供用户交互界面
2. **同步模块** - 负责从多个仓库获取和转换规则
3. **索引模块** - 创建和维护规则索引
4. **验证模块** - 验证规则的有效性和质量
5. **存储层** - 管理规则和索引的文件存储

### 架构图

```
+----------------+     +----------------+     +----------------+
|                |     |                |     |                |
|  命令行接口     |---->|    同步模块     |---->|    索引模块     |
|   (CLI)        |     |   (Sync)       |     |   (Indexing)   |
|                |     |                |     |                |
+----------------+     +----------------+     +----------------+
         |                    |                      |
         |                    v                      |
         |            +----------------+             |
         |            |                |             |
         +----------->|    验证模块     |<------------+
                      |  (Validation)  |
                      |                |
                      +----------------+
                              |
                              v
                      +----------------+
                      |                |
                      |    存储层       |
                      |   (Storage)    |
                      |                |
                      +----------------+
```

## 代码结构

RuleHub的代码结构按功能模块组织：

```
RuleHub/
├── rulehub.py                # 主入口脚本
├── requirements.txt          # 依赖项
├── config/                   # 配置文件
│   └── sources.yml           # 规则源配置
├── tools/                    # 工具模块
│   ├── cli/                  # 命令行接口
│   │   ├── __init__.py       # CLI初始化
│   │   ├── wizard.py         # 交互式向导
│   │   ├── commands/         # 命令实现
│   │   │   ├── rule_commands.py    # 规则管理命令
│   │   │   ├── repo_commands.py    # 仓库管理命令
│   │   │   ├── index_commands.py   # 索引管理命令
│   │   │   └── version_commands.py # 版本管理命令
│   │   └── utils/            # CLI工具类
│   │       └── cli_utils.py  # CLI辅助函数
│   ├── sync/                 # 同步模块
│   │   ├── sync_manager.py   # 同步管理器
│   │   ├── repo_handler.py   # 仓库处理器
│   │   └── rule_converter.py # 规则转换器
│   ├── indexing/             # 索引模块
│   │   └── indexer.py        # 索引生成器
│   ├── validation/           # 验证模块
│   │   ├── validator.py      # 规则验证器
│   │   ├── duplicate_detector.py  # 重复检测
│   │   ├── mitre_mapper.py   # MITRE映射
│   │   └── performance_analyzer.py # 性能分析
│   └── utils/                # 通用工具
│       └── file_utils.py     # 文件操作工具
├── rules/                    # 规则存储
├── index/                    # 索引存储
├── docs/                     # 文档
├── tests/                    # 测试
└── examples/                 # 示例
```

## 核心组件详解

### 命令行接口 (CLI)

命令行接口使用Python的`argparse`库实现，采用命令组和子命令的层次结构。主要文件：

- `tools/cli/__init__.py` - 初始化命令注册表
- `tools/cli/commands/` - 各类命令的实现
- `tools/cli/wizard.py` - 交互式向导实现

命令注册示例：

```python
# 在tools/cli/__init__.py中注册命令
registry.register_command('rule', 'list', list_rules, '列出规则')
```

### 同步模块

同步模块负责从外部仓库获取规则并转换为标准格式。主要组件：

- `tools/sync/sync_manager.py` - 协调同步过程
- `tools/sync/repo_handler.py` - 处理Git仓库操作
- `tools/sync/rule_converter.py` - 转换不同格式的规则

转换器基类：

```python
class RuleConverter(ABC):
    @abstractmethod
    def convert(self, rule_content: Dict, file_path: str) -> Dict:
        """将规则转换为标准格式"""
        pass
```

### 索引模块

索引模块负责创建和维护规则索引，支持高效搜索。主要文件：

- `tools/indexing/indexer.py` - 索引生成和搜索功能

索引类型：
- 主索引：包含所有规则详情
- 精简索引：仅包含基本信息
- 标签索引：按标签组织
- MITRE索引：按MITRE ATT&CK框架组织

### 验证模块

验证模块负责检查规则的质量和有效性。主要组件：

- `tools/validation/validator.py` - 规则验证
- `tools/validation/duplicate_detector.py` - 重复规则检测
- `tools/validation/mitre_mapper.py` - MITRE ATT&CK映射验证
- `tools/validation/performance_analyzer.py` - 规则性能分析

### 存储层

存储层以文件系统为基础，管理规则和索引的持久化存储。主要目录：

- `rules/` - 分类存储转换后的规则
- `index/` - 存储生成的索引文件
- `tmp/` - 临时文件存储

## 扩展系统

RuleHub设计为可扩展的系统，以下是常见的扩展点：

### 添加新的规则转换器

要支持新的规则格式，需要：

1. 在`tools/sync/rule_converter.py`中创建新的转换器类：

```python
class NewFormatConverter(RuleConverter):
    def convert(self, rule_content: Dict, file_path: str) -> Dict:
        # 实现转换逻辑
        standard_rule = self.get_standard_rule_template()
        
        # 填充标准规则
        standard_rule["id"] = rule_content.get("id", self.generate_rule_id("newformat"))
        standard_rule["name"] = rule_content.get("title", "")
        # ... 其他字段映射
        
        return standard_rule
```

2. 在`ConverterFactory`类中注册新转换器：

```python
@staticmethod
def get_converter(source_type: str) -> RuleConverter:
    # ... 现有代码 ...
    elif source_type.lower() == 'newformat':
        return NewFormatConverter()
    # ... 现有代码 ...
```

### 添加新的命令

要添加新命令，需要：

1. 在相应的命令文件中实现命令函数：

```python
# 在tools/cli/commands/rule_commands.py中
def export_rules(args):
    """导出规则到特定格式"""
    # 实现导出逻辑
```

2. 在`tools/cli/__init__.py`中注册命令：

```python
registry.register_command('rule', 'export', export_rules, '导出规则到特定格式')
```

3. 在`rulehub.py`中更新参数解析器，为新命令添加参数：

```python
if group == "rule" and cmd_name == "export":
    cmd_parser.add_argument("--format", choices=["sigma", "stix"], required=True, help="导出格式")
    cmd_parser.add_argument("--output", required=True, help="输出文件路径")
```

### 增强验证功能

要添加新的验证检查，需要：

1. 在`tools/validation/`目录中创建新的验证器类或扩展现有验证器：

```python
class EnhancedValidator(Validator):
    def validate_rule_quality(self, rule: Dict) -> List[ValidationResult]:
        results = []
        
        # 实现新的验证逻辑
        if not rule.get("references"):
            results.append(ValidationResult(
                level="warning",
                message="规则缺少引用链接",
                rule_id=rule.get("id", "未知")
            ))
        
        return results
```

2. 在验证过程中使用新验证器：

```python
# 在tools/cli/commands/rule_commands.py的validate_rule函数中
validator = EnhancedValidator()
results = validator.validate(rule)
```

## 最佳实践

### 代码风格

RuleHub遵循PEP 8代码风格指南：

- 使用4个空格缩进
- 使用小写下划线命名法(snake_case)命名变量和函数
- 使用驼峰命名法(CamelCase)命名类
- 使用描述性的变量名和函数名
- 添加清晰的文档字符串

### 版本控制

版本号格式：`主版本.次版本.修订版本`

- 主版本：不兼容的API变更
- 次版本：向后兼容的功能增加
- 修订版本：向后兼容的bug修复

### 测试策略

编写单元测试和集成测试，放在`tests/`目录下：

- 单元测试：测试独立函数和类
- 集成测试：测试组件间交互
- 使用测试夹具(fixtures)模拟数据

### 优化建议

- **性能优化**
  - 使用并行处理大量规则
  - 实现增量同步和索引更新
  - 优化规则存储结构

- **内存优化**
  - 处理大量规则时使用流处理
  - 避免一次性加载大型索引

## 排障指南

### 调试日志

增加日志详细程度：

```python
logging.basicConfig(
    level=logging.DEBUG,  # 从INFO改为DEBUG
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('rulehub_debug.log')
    ]
)
```

### 常见开发问题

1. **规则转换失败**
   - 检查原始规则格式是否符合预期
   - 确认转换器逻辑处理了所有边缘情况

2. **命令注册问题**
   - 确保命令已正确注册到注册表
   - 检查参数解析器配置

3. **索引生成错误**
   - 确保规则格式符合预期
   - 检查文件权限和磁盘空间

4. **Git操作失败**
   - 检查网络连接和认证信息
   - 确认仓库URL和分支名称正确

## API文档

详细的API文档请参考[API参考](api_reference.md)。

## 贡献指南

如果您想要贡献代码，请参考[贡献指南](contributing.md)。