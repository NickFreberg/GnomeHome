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


def test_migrate_then_db_status(config_path, capsys):
    assert cli.main(["--config", str(config_path), "migrate"]) == 0
    assert "schema version 3" in capsys.readouterr().out
    assert cli.main(["--config", str(config_path), "db-status"]) == 0
    out = capsys.readouterr().out
    assert "journal mode     wal" in out
    assert "audit_log" in out


def test_audit_verify_on_fresh_database(config_path, capsys):
    cli.main(["--config", str(config_path), "migrate"])
    assert cli.main(["--config", str(config_path), "audit-verify"]) == 0
    assert "chain intact" in capsys.readouterr().out


def test_scan_dry_run_prints_commands_and_problems(config_path, capsys):
    assert cli.main(["--config", str(config_path), "scan", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "--excludefile" in out
    assert "192.0.2.10" in out
    assert "These would stop a real scan" in out  # example values and TEST-NET target


def test_real_scan_with_example_config_is_refused_before_anything_is_sent(config_path, capsys):
    assert cli.main(["--config", str(config_path), "scan"]) == 1
    assert "REFUSED (nothing was sent)" in capsys.readouterr().err
    assert not (config_path.parent.parent / "data" / "gnomehome.sqlite3").exists()


def test_synth_then_synth_load_uses_the_dev_database(config_path, capsys):
    base = ["--config", str(config_path)]
    assert cli.main([*base, "synth", "--seed", "3", "--days", "1"]) == 0
    assert cli.main([*base, "synth-load", "--seed", "3"]) == 0
    out = capsys.readouterr().out
    assert "dropped by the protected-asset guard" in out
    data = config_path.parent.parent / "data"
    assert (data / "dev.sqlite3").exists()
    assert not (data / "gnomehome.sqlite3").exists()  # the real DB is never touched


def test_synth_load_without_data_explains_what_to_do(config_path, capsys):
    assert cli.main(["--config", str(config_path), "synth-load", "--seed", "999"]) == 1
    assert "just synth" in capsys.readouterr().err
