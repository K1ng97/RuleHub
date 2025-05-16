# RuleHub

RuleHub是一个网络安全检测规则仓库系统，用于统一管理、转换和索引来自多个开源社区的安全检测规则。

## 功能特点

- 自动同步多个开源规则仓库
- 规则格式转换和标准化
- 规则索引和搜索
- 统一的规则管理接口

## 目录结构

```
RuleHub/
├── config/             # 配置文件目录
│   └── sources.yml     # 规则源配置
├── rules/              # 规则存储目录
│   ├── sigma/          # Sigma规则
│   ├── elastic/        # Elastic规则
│   ├── splunk/         # Splunk规则
│   └── other/          # 其他来源规则
├── tools/              # 工具脚本目录
│   ├── sync/           # 同步工具
│   ├── indexing/       # 索引工具
│   ├── validation/     # 验证工具
│   └── utils/          # 通用工具类
└── docs/               # 文档目录
```

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 同步规则

```bash
python -m tools.sync.sync_manager
```

### 生成索引

```bash
python -m tools.indexing.indexer
```

## 配置说明

在`config/sources.yml`中配置规则源信息，包括仓库URL、分支、规则目录路径等。

## 开发环境

- Python 3.8+
- PyYAML
- GitPython
- JSON Schema