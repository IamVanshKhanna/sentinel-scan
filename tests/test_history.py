import subprocess

import pytest

from sentinel_scan.history import is_git_repo, scan_history


def _run(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


@pytest.fixture
def repo_with_removed_secret(tmp_path):
    _run(tmp_path, "init", "-q")
    _run(tmp_path, "config", "user.email", "test@example.com")
    _run(tmp_path, "config", "user.name", "Test")

    secret_file = tmp_path / "config.py"
    secret_file.write_text('AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
    _run(tmp_path, "add", ".")
    _run(tmp_path, "commit", "-q", "-m", "add config with secret")

    secret_file.write_text('AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY"]\n')
    _run(tmp_path, "add", ".")
    _run(tmp_path, "commit", "-q", "-m", "remove hardcoded secret")

    return tmp_path


def test_is_git_repo_true_for_real_repo(repo_with_removed_secret):
    assert is_git_repo(str(repo_with_removed_secret)) is True


def test_is_git_repo_false_for_non_repo(tmp_path):
    assert is_git_repo(str(tmp_path)) is False


def test_history_finds_secret_removed_from_head(repo_with_removed_secret):
    findings = scan_history(str(repo_with_removed_secret))
    assert len(findings) == 1
    assert findings[0].kind == "aws_access_key"
    assert findings[0].file == "config.py"


def test_history_scan_on_non_repo_fails_soft(tmp_path):
    assert scan_history(str(tmp_path)) == []
