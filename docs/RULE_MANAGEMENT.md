# RuleHub 规则管理文档

## 同步机制
1. **自动同步开源规则**
   - 通过GitHub Actions定期执行同步任务
   - 使用`sync_rules.py`脚本同步配置的规则仓库
   - 同步后自动创建Pull Request到`develop`分支

2. **同步流程**
   - 检查远程仓库是否有更新(通过commit hash比对)
   - 使用rsync同步规则文件到本地仓库
   - 更新版本元数据文件`version_metadata.json`
   - 自动提交变更并创建Pull Request

3. **同步频率**
   - 默认每小时同步一次
   - 可通过`workflow_dispatch`手动触发

## 分支策略
1. `main`分支: 存放已通过审批的稳定版本规则
2. `develop`分支: 用于日常开发和规则更新
3. 功能分支: 按`feature/规则类型-描述`格式命名

## 审批流程
1. 提交Pull Request到`develop`分支
2. 至少需要1名审核人员批准
3. 通过CI测试
4. 合并到`main`分支后生效

## 规则提交规范
1. 自定义规则需放在`rules/private`对应目录下
2. 文件名需清晰描述规则用途
3. 需包含完整的规则元数据