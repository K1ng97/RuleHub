# 背景
现在计划搭建一个托管在github上的规则仓库，用于维护庞杂的网络安全检测规则，如suricata、sigma规则等，这个仓库的主要规则来源是一些开源的规则项目中的规则，如sigma，以及用户自定义开发的规则，而且这个仓库在搭建完成后，还要实时获取来自开源规则仓库的更新，并且不管是更新开源规则还是用户添加自定义规则，都要进行版本控制和审批，通过审批的更新才能被存入仓库。

# 实现过程
1. 创建仓库: 在我的 GitHub 上创建一个名为 RuleHub 的仓库，并且和当前项目绑定。
2. 按照项目结构生成目录。
3. 规划结构和分支: 设计好规则分类目录和版本控制策略。
4. 初始化仓库: 拉取开源 sigma 仓库的规则目录到本仓库目录。
5. 编写自动化 Action: 创建 GitHub Action 来定期同步更新开源规则。
6. 完善相关的文档记录。

# 项目结构
```
RuleHub/
├── rules/                     # 本地规则仓库 (Git 仓库)
│   ├── public/                # 存放 Github 上的开源规则项目
│   │   ├── sigma/             # SigmaHQ 开源规则项目 https://github.com/SigmaHQ/sigma
│   │   ├── elastic/           # Elastic 开源规则项目 https://github.com/elastic/detection-rules
│   │   ├── splunk/            # Splunk 开源规则项目 https://research.splunk.com/detections/
│   ├── private/               # 私有的自定义开发规则
│   │   ├── sigma/
│   │   │   ├── windows/
│   │   │   ├── linux/
│   │   │   ├── macos/
│   │   │   ├── compliance/
│   │   ├── splunk/
│   │   │   ├── windows/
│   │   │   ├── linux/
│   │   │   ├── macos/
│   │   │   ├── compliance/
│   │   ├── elk/
│   │   │   ├── windows/
│   │   │   ├── linux/
│   │   │   ├── macos/
│   │   │   └── compliance/
├── docs/                      # 项目相关文档
└── README.md
```