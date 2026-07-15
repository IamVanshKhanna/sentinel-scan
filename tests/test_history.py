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
    result = scan_history(str(repo_with_removed_secret))
    assert result.ok is True
    assert len(result.findings) == 1
    assert result.findings[0].kind == "aws_access_key"
    assert result.findings[0].file == "config.py"


def test_history_scan_on_non_repo_is_a_valid_noop_not_a_failure(tmp_path):
    """Not being a git repo is expected and common — it must report ok=True, not look
    like the history scan crashed."""
    result = scan_history(str(tmp_path))
    assert result.ok is True
    assert result.findings == []


def test_history_scan_reports_not_ok_on_git_command_failure(tmp_path, monkeypatch):
    """An actual git command failure (as opposed to 'not a repo') must be distinguishable
    from a clean scan — same fail-open concern already fixed for the OSV dependency check."""
    import subprocess as sp

    from sentinel_scan import history as history_module

    monkeypatch.setattr(history_module, "is_git_repo", lambda path: True)

    def fake_run(*args, **kwargs):
        raise sp.TimeoutExpired(cmd="git log -p", timeout=60)

    monkeypatch.setattr(sp, "run", fake_run)
    result = scan_history(str(tmp_path))
    assert result.ok is False
    assert result.findings == []
