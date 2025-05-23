# RuleHub 贡献指南

感谢您考虑为RuleHub项目做出贡献！本文档将指导您如何参与项目开发、提交代码和报告问题。

## 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
  - [报告Bug](#报告bug)
  - [提出功能建议](#提出功能建议)
  - [提交代码](#提交代码)
- [开发流程](#开发流程)
  - [环境设置](#环境设置)
  - [分支策略](#分支策略)
  - [提交规范](#提交规范)
  - [代码审查](#代码审查)
- [代码风格](#代码风格)
  - [Python风格指南](#python风格指南)
  - [文档风格](#文档风格)
  - [注释规范](#注释规范)
- [测试指南](#测试指南)
  - [编写测试](#编写测试)
  - [运行测试](#运行测试)
- [文档贡献](#文档贡献)
- [版本发布流程](#版本发布流程)
- [联系方式](#联系方式)

## 行为准则

本项目采用开放、尊重和包容的社区环境。参与者应保持尊重，避免贬低、歧视或骚扰行为。

## 如何贡献

### 报告Bug

如果您发现了Bug，请通过Issue报告，包含以下信息：

1. 问题的简要描述
2. 重现步骤
3. 期望的行为
4. 实际的行为
5. 环境信息（操作系统、Python版本等）
6. 相关日志和截图（如有）

请使用以下模板：

```
## Bug描述
[简要描述Bug]

## 重现步骤
1. [第一步]
2. [第二步]
3. [...]

## 期望的行为
[描述期望看到的结果]

## 实际的行为
[描述实际发生的结果]

## 环境信息
- 操作系统: [例如: Windows 10, Ubuntu 20.04]
- Python版本: [例如: 3.8.5]
- RuleHub版本: [例如: 1.0.0]

## 其他信息
[日志、截图等其他相关信息]
```

### 提出功能建议

如果您有功能建议，请通过Issue提出，包含以下信息：

1. 功能的简要描述
2. 功能的使用场景
3. 实现的可能方式（如有）

请使用以下模板：

```
## 功能描述
[简要描述您的功能建议]

## 使用场景
[描述该功能的适用场景和价值]

## 实现建议
[如有实现建议，请在此描述]

## 其他信息
[其他相关信息]
```

### 提交代码

1. Fork项目仓库
2. 创建特性分支
3. 提交您的更改
4. 确保测试通过
5. 提交Pull Request

## 开发流程

### 环境设置

1. 克隆仓库：

```bash
git clone https://github.com/your-username/rulehub.git
cd rulehub
```

2. 创建虚拟环境：

```bash
python -m venv venv
source venv/bin/activate  # 在Windows上使用: venv\Scripts\activate
```

3. 安装依赖：

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # 开发依赖
```

### 分支策略

我们使用以下分支策略：

- `main`: 主分支，保持稳定
- `develop`: 开发分支，包含下一版本的最新代码
- `feature/*`: 特性分支，用于开发新功能
- `bugfix/*`: 修复分支，用于修复Bug
- `release/*`: 发布分支，用于准备新版本发布
- `hotfix/*`: 热修复分支，用于紧急修复生产问题

### 提交规范

提交信息应使用清晰、描述性的语言，遵循以下格式：

```
<类型>(<范围>): <描述>

[可选的详细描述]

[可选的关闭Issue引用]
```

类型包括：
- `feat`: 新功能
- `fix`: Bug修复
- `docs`: 文档更改
- `style`: 代码风格更改（不影响代码运行）
- `refactor`: 代码重构
- `perf`: 性能优化
- `test`: 添加或修改测试
- `chore`: 构建过程或辅助工具的变动

示例：
```
feat(sync): 添加增量同步功能

添加了仅同步更新的规则的功能，减少网络流量和处理时间。

Closes #123
```

### 代码审查

所有代码提交都需要通过代码审查。请遵循以下准则：

1. 保持提交内容相对较小，便于审查
2. 清晰解释代码更改的目的和实现方式
3. 确保所有测试通过
4. 及时响应审查意见

## 代码风格

### Python风格指南

RuleHub项目遵循[PEP 8](https://www.python.org/dev/peps/pep-0008/)风格指南，主要规范包括：

1. 使用4个空格进行缩进，不使用制表符
2. 每行代码不超过100个字符
3. 使用空行分隔函数和类
4. 在运算符周围使用空格
5. 使用小写下划线命名法命名函数和变量（如`calculate_total`）
6. 使用驼峰命名法命名类（如`RuleConverter`）
7. 使用全大写命名常量（如`MAX_RETRY_COUNT`）

我们使用以下工具确保代码质量：

- `black`: 代码格式化
- `isort`: 导入排序
- `flake8`: 代码风格检查
- `mypy`: 类型检查

### 文档风格

1. 使用Markdown格式编写文档
2. 保持文档与代码同步更新
3. 使用清晰、简洁的语言
4. 包含示例和用例
5. 为复杂功能提供图表或流程图

### 注释规范

1. 使用文档字符串(docstring)为模块、类、方法和函数提供文档：

```python
def convert_rule(rule_content: Dict, rule_type: str) -> Dict:
    """
    将规则转换为标准格式
    
    Args:
        rule_content: 原始规则内容
        rule_type: 规则类型
        
    Returns:
        Dict: 标准格式的规则
        
    Raises:
        ValueError: 如果规则类型不受支持
    """
    # 实现代码
```

2. 对于复杂的逻辑，使用行内注释解释

3. 更新功能时同步更新注释

## 测试指南

### 编写测试

我们使用`pytest`进行测试。请为所有新功能和修复编写测试，包括：

1. 单元测试：测试独立函数和类
2. 集成测试：测试组件间交互
3. 端到端测试：测试完整功能流程

测试文件命名规范：`test_<module_name>.py`

测试函数命名规范：`test_<function_name>_<scenario>`

测试示例：

```python
# test_rule_converter.py
def test_sigma_converter_basic():
    """测试基本的Sigma规则转换"""
    # 测试代码
    
def test_sigma_converter_empty_tags():
    """测试处理空标签的情况"""
    # 测试代码
```

### 运行测试

运行所有测试：

```bash
pytest
```

运行特定测试文件：

```bash
pytest tests/test_sync.py
```

运行特定测试函数：

```bash
pytest tests/test_sync.py::test_sync_all
```

使用覆盖率报告：

```bash
pytest --cov=tools tests/
```

## 文档贡献

如果您想贡献文档，请遵循以下准则：

1. 使用Markdown格式
2. 保持语言简洁明了
3. 包含实际示例
4. 更新目录和索引
5. 检查拼写和语法
6. 确保链接有效

## 版本发布流程

版本号格式：`主版本.次版本.修订版本`（如`1.0.0`）

发布流程：

1. 在`develop`分支上完成功能开发和测试
2. 创建`release/vX.Y.Z`分支
3. 在发布分支上完成最终测试和修复
4. 更新版本号和变更日志
5. 合并到`main`分支并创建标签
6. 合并回`develop`分支

## 联系方式

如有任何问题，请通过Issue或以下方式联系项目维护者：

- 电子邮件：[project@example.com](mailto:project@example.com)
- 论坛：[https://example.com/forum](https://example.com/forum)

---

再次感谢您对RuleHub项目的贡献！