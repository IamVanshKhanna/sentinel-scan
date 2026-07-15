import os

from sentinel_scan.secrets import scan_directory, scan_file, shannon_entropy

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_clean_file_has_no_findings():
    findings = scan_file(os.path.join(FIXTURES, "clean_file.py"))
    assert findings == []


def test_planted_secrets_are_detected():
    findings = scan_file(os.path.join(FIXTURES, "planted_secrets.py"))
    kinds = {f.kind for f in findings}
    assert "aws_access_key" in kinds
    assert "github_token" in kinds
    assert "private_key_header" in kinds
    assert "generic_secret_assignment" in kinds


def test_planted_secrets_have_expected_severities():
    findings = scan_file(os.path.join(FIXTURES, "planted_secrets.py"))
    by_kind = {f.kind: f.severity for f in findings}
    assert by_kind["aws_access_key"] == "critical"
    assert by_kind["github_token"] == "critical"
    assert by_kind["private_key_header"] == "critical"


def test_entropy_low_for_normal_words():
    assert shannon_entropy("hello") < 3.0
    assert shannon_entropy("") == 0.0


def test_entropy_high_for_random_string():
    assert shannon_entropy("aK9$xQ2!zR7mP4wL8vB1nC6") > 4.3


def test_lockfiles_are_skipped_not_flagged():
    """package-lock.json integrity hashes are legitimate high-entropy strings, not secrets."""
    findings = scan_directory(FIXTURES)
    lockfile_findings = [f for f in findings if f.file.endswith("package-lock.json")]
    assert lockfile_findings == []


def test_sentinelignore_suppresses_listed_file():
    findings = scan_directory(os.path.join(FIXTURES, "ignore-test"))
    ignored = [f for f in findings if "ignored_secret.py" in f.file]
    assert ignored == []


def test_inline_ignore_marker_suppresses_line():
    findings = scan_directory(os.path.join(FIXTURES, "ignore-test"))
    inline = [f for f in findings if "inline_ignore.py" in f.file]
    assert inline == []


def test_stripe_key_detected():
    findings = scan_file(os.path.join(FIXTURES, "planted_secrets.py"))
    kinds = {f.kind for f in findings}
    assert "stripe_live_key" in kinds


def test_jwt_detected():
    findings = scan_file(os.path.join(FIXTURES, "planted_secrets.py"))
    kinds = {f.kind for f in findings}
    assert "jwt_token" in kinds


def test_db_connection_string_detected():
    findings = scan_file(os.path.join(FIXTURES, "planted_secrets.py"))
    kinds = {f.kind for f in findings}
    assert "db_connection_string_with_creds" in kinds


def test_pem_file_flagged_by_filename():
    findings = scan_file(os.path.join(FIXTURES, "fake.pem"))
    kinds = {f.kind for f in findings}
    assert "pem_key_file" in kinds


def test_shell_env_var_reference_not_flagged(tmp_path):
    """TOKEN="${TELEGRAM_BOT_TOKEN:-}" is a bash default-value pattern, not a literal secret."""
    f = tmp_path / "script.sh"
    f.write_text('TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"\n')
    findings = scan_file(str(f))
    assert findings == []
