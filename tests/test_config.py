import json

import pytest

from dnspector.config import load_config


class TestLoadConfig:
    def test_no_path_returns_empty_dict(self):
        assert load_config(None) == {}

    def test_nonexistent_file_returns_empty_dict(self, tmp_path):
        assert load_config(str(tmp_path / "missing.json")) == {}

    def test_valid_config_is_loaded(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"duration": 30, "entropy_threshold": 4.0}))
        assert load_config(str(config_file)) == {"duration": 30, "entropy_threshold": 4.0}

    def test_malformed_config_raises_value_error(self, tmp_path):
        config_file = tmp_path / "bad.json"
        config_file.write_text("{not valid json")
        with pytest.raises(ValueError):
            load_config(str(config_file))
