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


def test_protected_check_flags_example_values(config_path, capsys):
    assert cli.main(["--config", str(config_path), "protected-check"]) == 1
    captured = capsys.readouterr()
    assert "Work laptop: 2 MAC(s), 1 IP/CIDR(s)" in captured.out
    assert "00:00:5e" not in captured.out  # never prints identifiers
    assert "example values" in captured.err


def test_protected_check_missing_list(config_path, capsys):
    (config_path.parent / "protected_assets.yaml").unlink()
    assert cli.main(["--config", str(config_path), "protected-check"]) == 1
    assert "not found" in capsys.readouterr().err


def test_protected_filter_prints_tcpdump_expression(config_path, capsys):
    assert cli.main(["--config", str(config_path), "protected-filter"]) == 0
    assert capsys.readouterr().out.strip() == (
        "host 192.0.2.10 or ether host 00:00:5e:00:53:01 or ether host 00:00:5e:00:53:02"
    )
