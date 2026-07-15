import pytest

from sentinel_scan.cli import main


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert "sentinel-scan" in capsys.readouterr().out


def test_exclude_flag_suppresses_matching_file(tmp_path, capsys):
    secret_file = tmp_path / "secret.py"
    secret_file.write_text('AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

    exit_code = main([str(tmp_path), "--no-deps", "--exclude", "secret.py", "--json"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert '"secrets": []' in out


def test_exclude_absent_still_finds_secret(tmp_path, capsys):
    secret_file = tmp_path / "secret.py"
    secret_file.write_text('AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

    exit_code = main([str(tmp_path), "--no-deps", "--json"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "aws_access_key" in out


def test_fail_on_returns_nonzero_when_finding_exists(tmp_path):
    secret_file = tmp_path / "secret.py"
    secret_file.write_text('AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

    exit_code = main([str(tmp_path), "--no-deps", "--fail-on", "critical"])
    assert exit_code == 1


def test_fail_on_returns_zero_when_clean(tmp_path):
    clean_file = tmp_path / "clean.py"
    clean_file.write_text("x = 1\n")

    exit_code = main([str(tmp_path), "--no-deps", "--fail-on", "critical"])
    assert exit_code == 0
