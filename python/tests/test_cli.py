from gnomehome import __version__, cli


def test_help_with_no_command_returns_zero(capsys):
    assert cli.main([]) == 0
    assert "gnomehome" in capsys.readouterr().out


def test_version_is_set():
    assert __version__.count(".") == 2
