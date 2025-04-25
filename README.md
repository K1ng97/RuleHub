# RuleHub

## 项目简介
RuleHub是一个集中管理网络安全检测规则的仓库，整合了多个开源规则项目(SigmaHQ、Elastic、Splunk等)的规则，同时支持自定义规则的开发和管理。

## 主要功能
- 自动同步多个开源规则仓库
- 支持自定义规则开发
- 严格的版本控制和审批流程
- 规则分类存储和管理

## 项目结构
```
RuleHub/
├── rules/                     # 本地规则仓库 (Git 仓库)
│   ├── public/                # 存放 Github 上的开源规则项目
│   │   ├── sigma/             # SigmaHQ 开源规则项目
│   │   ├── elastic/           # Elastic 开源规则项目
│   │   ├── splunk/            # Splunk 开源规则项目
│   ├── private/               # 私有的自定义开发规则
│   │   ├── sigma/
│   │   ├── splunk/
│   │   ├── elk/
├── docs/                      # 项目相关文档
└── scripts/                   # 自动化脚本
```

## 使用说明
1. 克隆仓库: `git clone https://github.com/K1ng97/RuleHub.git`
2. 配置同步: 修改`config.yml`文件配置需要同步的规则仓库
3. 自动同步: GitHub Action会自动定期同步规则
4. 自定义规则: 在`rules/private/`目录下添加自定义规则

## 文档
- [规则管理文档](docs/RULE_MANAGEMENT.md)
- [分支策略](docs/BRANCH_POLICY.md)