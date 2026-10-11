from gnomehome import __version__, cli


def test_help_with_no_command_returns_zero(capsys):
    assert cli.main([]) == 0
    assert "gnomehome" in capsys.readouterr().out


def test_version_is_set():
    assert __version__.count(".") == 2


def test_doctor_runs_against_example_config(config_path, capsys):
    assert cli.main(["--config", str(config_path), "doctor"]) == 0
    out = capsys.readouterr().out
    assert "platform" in out
    assert "en0" in out


def test_bad_config_exits_with_code_2(tmp_path, capsys):
    assert cli.main(["--config", str(tmp_path / "missing.toml"), "doctor"]) == 2
    assert "config error" in capsys.readouterr().err
