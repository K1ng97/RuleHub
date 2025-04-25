# RuleHub 网络安全规则仓库

## 项目介绍
RuleHub是一个集中管理网络安全检测规则的仓库，包含来自多个开源项目的规则以及用户自定义规则。

## 主要功能
- 自动同步多个开源规则仓库(SigmaHQ, Elastic, Splunk)
- 支持自定义规则开发和管理
- 完善的版本控制和审批流程

## 项目结构
```
RuleHub/
├── rules/                     # 本地规则仓库
│   ├── public/                # 开源规则
│   │   ├── sigma/             # SigmaHQ规则
│   │   ├── elastic/           # Elastic规则
│   │   ├── splunk/            # Splunk规则
│   ├── private/               # 自定义规则
├── docs/                      # 项目文档
└── .github/workflows/         # GitHub Actions工作流
```

## 使用说明
1. 克隆仓库: `git clone https://github.com/K1ng97/RuleHub.git`
2. 查看规则: 在`rules`目录下浏览相应规则
3. 添加自定义规则: 在`rules/private`相应目录下添加规则文件
4. 提交PR进行规则审批

## 同步机制
- 自动同步: 通过GitHub Actions定期同步开源规则
- 手动同步: 可触发`workflow_dispatch`事件手动同步