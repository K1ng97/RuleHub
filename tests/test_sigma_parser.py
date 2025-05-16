import pytest
import yaml
from pathlib import Path
from tools.parsers.sigma_parser import SigmaParser, SigmaParserConfig
from datetime import datetime


@pytest.fixture
def sample_rule(tmp_path):
    # 创建临时规则文件
    rule_path = tmp_path / "test_rule.yml"
    rule_content = {
        "id": "12345",
        "title": "Test Rule",
        "description": "Test Description",
        "author": "Test Author",
        "date": datetime(2024, 1, 1),
        "status": "stable",
        "tags": ["test"],
        "logsource": {"product": "test"}
    }
    with open(rule_path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(rule_content, f)
    return rule_path


@pytest.fixture
def invalid_rule(tmp_path):
    # 创建无效YAML规则文件
    rule_path = tmp_path / "invalid_rule.yml"
    with open(rule_path, 'w', encoding='utf-8') as f:
        f.write("invalid: yaml: [content")
    return rule_path


def test_parse_valid_rule(sample_rule):
    parser = SigmaParser(SigmaParserConfig())
    meta = parser.parse(sample_rule)
    assert meta["id"] == "12345"
    assert meta["name"] == "Test Rule"
    assert meta["date"] == "2024-01-01"


def test_parse_invalid_rule(invalid_rule, caplog):
    parser = SigmaParser(SigmaParserConfig())
    meta = parser.parse(invalid_rule)
    assert meta is None
    assert "解析Sigma规则文件" in caplog.text
    assert "失败" in caplog.text


def test_parse_directory(tmp_path, sample_rule):
    # 创建测试目录结构
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "subdir").mkdir()
    sample_rule.rename(rules_dir / "test_rule.yml")  # 移动到测试目录
    (rules_dir / "subdir" / "another_rule.yml").write_text("id: 67890\ntitle: Another Rule\n")

    config = SigmaParserConfig()
    config.rules_dir = rules_dir  # 覆盖配置路径
    parser = SigmaParser(config)
    metadata_list = parser.parse_directory()

    assert len(metadata_list) >= 1  # 至少解析成功1个文件
    assert any(meta["id"] == "12345" for meta in metadata_list)


def test_save_to_json(tmp_path):
    test_metadata = [{"name": "Test", "id": "123"}]
    output_path = tmp_path / "test_output.json"

    parser = SigmaParser(SigmaParserConfig())
    result = parser.save_to_json(test_metadata, output_path)
    assert result is True
    assert output_path.exists()


def test_config_default_path(caplog):
    # 测试配置文件不存在时使用默认路径
    non_existent_config = Path("non_existent_config.yaml")
    config = SigmaParserConfig(non_existent_config)
    assert config.rules_dir == Path("../../rules/sigma")
    assert "配置文件" in caplog.text
    assert "未找到" in caplog.text


if __name__ == '__main__':
    pytest.main([__file__])