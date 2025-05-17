# RuleHub

这是一个规则同步和解析的项目，主要功能包括从多个源同步规则，解析不同格式的规则文件并生成索引。

## 项目结构
```
.github/
  workflows/
    daily-sync.yml
    python-checks.yml
    release.yml
    rule-validation.yml
.gitignore
.trae/
  rules/
    project_rules.md
CHANGELOG.md
CODEOWNERS
Dockerfile
README.md
config/
  sigma_parser_config.yaml
  sources.yml
debug_sync.py
docker-compose.yml
docs/
  api_reference.md
  cli_usage.md
  contributing.md
  developer_guide.md
  rule_format.md
  usage.md
  user_guide.md
examples/
  custom/
    network_scanning_detection.json
  elastic/
    windows_registry_persistence_run_keys.json
  sigma/
    windows_powershell_suspicious_parameter_variation.yml
index/
  custom_index.json
  elastic_index.json
  index_stats.json
  mitre_index.json
  other_index.json
  rules_index.json
  rules_index_compact.json
  sigma_index.json
  sigma_metadata.json
  splunk_index.json
  tags_index.json
requirements.txt
rulehub.py
rules/
  custom/
    splunk/
  elastic/
    README.md
    _deprecated/
    apm/
    cross-platform/
    integrations/
    linux/
    macos/
    ml/
    network/
    promotions/
    threat_intel/
    windows/
  sigma/
    README.md
    application/
    category/
    cloud/
    compliance/
    linux/
    macos/
    network/
    web/
    windows/
  splunk/
    application/
    cloud/
    deprecated/
    endpoint/
    network/
    web/
stats/
  sync_stats.json
tests/
  fixtures/
    test_custom_rule.json
    test_elastic_rule.json
    test_sigma_rule.yml
    test_splunk_rule.yml
  test_cli.py
  test_indexing.py
  test_sigma_parser.py
  test_sync.py
  test_validation.py
tmp/
  repos/
    elastic/
    sigma/
    splunk/
tools/
  cli/
    __init__.py
    commands/
    utils/
    wizard.py
  indexing/
    indexer.py
  parsers/
    __init__.py
    elastic_parser.py
    sigma_parser.py
    splunk_parser.py
  sync/
    repo_handler.py
    rule_converter.py
    sync_manager.py
  utils/
    file_utils.py
  validation/
    duplicate_detector.py
    mitre_mapper.py
    performance_analyzer.py
    validator.py
versions/
  latest.json
  v2.0.0.json
```

## 功能说明
- **规则同步**：从多个源同步规则到本地。
- **规则解析**：解析 Elastic、Sigma 和 Splunk 格式的规则文件，提取元数据并保存为 JSON 文件。
- **索引生成**：根据解析后的规则生成索引文件。

## 使用方法
1. 安装依赖：`pip install -r requirements.txt`
2. 配置规则源：编辑 `config/sources.yml` 文件。
3. 同步规则：`python3 rulehub.py repo sync`
4. 解析规则并生成索引：同步完成后自动执行。

## 开发指南
详见 `docs/developer_guide.md` 文件。

## 贡献指南
详见 `docs/contributing.md` 文件。