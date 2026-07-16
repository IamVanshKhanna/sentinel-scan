import os

from sentinel_scan.secrets import (
    is_binary,
    scan_directory,
    scan_directory_with_stats,
    scan_file,
    shannon_entropy,
)

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


def test_is_binary_detects_null_bytes(tmp_path):
    binary_file = tmp_path / "binary.dat"
    binary_file.write_bytes(b"\x00\x01\x02\xff\xfe")
    assert is_binary(str(binary_file)) is True


def test_is_binary_false_for_text_file(tmp_path):
    text_file = tmp_path / "text.txt"
    text_file.write_text("just plain text\n")
    assert is_binary(str(text_file)) is False


def test_binary_file_content_not_scanned_but_filename_check_still_runs(tmp_path):
    """A binary .pem file should still be flagged by filename, but not content-scanned."""
    binary_pem = tmp_path / "binary.pem"
    binary_pem.write_bytes(b"\x00\x01" + b"AKIAABCDEFGHIJKLMNOP")  # secret-shaped bytes after null byte
    findings = scan_file(str(binary_pem))
    kinds = {f.kind for f in findings}
    assert "pem_key_file" in kinds  # filename check still fires
    assert "aws_access_key" not in kinds  # content was never line-scanned


def test_oversized_file_is_skipped(tmp_path, monkeypatch):
    from sentinel_scan import secrets as secrets_module
    monkeypatch.setattr(secrets_module, "MAX_FILE_SIZE_BYTES", 10)  # artificially tiny cap
    f = tmp_path / "big.py"
    f.write_text('AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')  # well over 10 bytes
    findings = scan_file(str(f))
    assert findings == []


def test_no_double_report_when_regex_and_entropy_both_would_match(tmp_path):
    """A line matched by a named pattern shouldn't also generate a separate entropy finding."""
    f = tmp_path / "config.py"
    f.write_text('api_key = "aK9xQ2zR7mP4wL8vB1nC6dE3fG5hJ0kM"\n')
    findings = scan_file(str(f))
    kinds = [x.kind for x in findings]
    assert kinds.count("generic_secret_assignment") == 1
    assert "high_entropy_string" not in kinds


def test_second_independent_secret_on_same_line_still_reported(tmp_path):
    """A regex match earlier on a line must not blanket-suppress a genuinely separate
    high-entropy secret later on the same line — that's a real finding getting dropped,
    not noise reduction."""
    f = tmp_path / "config.py"
    f.write_text(
        'api_key = "aK9xQ2zR7mP4wL8vB1nC6dE3fG5hJ0kM"; '
        'backup_token = "zR7mK9xQ2vB1nC6dE3fG5hJ0kMaK9xQ2z"\n'
    )
    findings = scan_file(str(f))
    kinds = [x.kind for x in findings]
    assert kinds.count("generic_secret_assignment") == 2


def test_scan_directory_extra_ignore_patterns(tmp_path):
    f = tmp_path / "secret.py"
    f.write_text('AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
    findings = scan_directory(str(tmp_path), extra_ignore_patterns=["secret.py"])
    assert findings == []


def test_inline_ignore_marker_is_counted_not_just_silently_dropped(tmp_path):
    """Inline suppressions must be visible in aggregate, same principle as the
    .sentinelignore/--exclude file-level suppression count."""
    f = tmp_path / "config.py"
    f.write_text(
        'AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"  # sentinel-scan:ignore\n'
        'x = 1\n'
    )
    result = scan_directory_with_stats(str(tmp_path))
    assert result.findings == []
    assert result.inline_suppressed_count == 1


def test_ignored_file_count_and_inline_count_are_independent(tmp_path):
    (tmp_path / "a.py").write_text('AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"  # sentinel-scan:ignore\n')
    (tmp_path / "b.py").write_text('AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
    result = scan_directory_with_stats(str(tmp_path), extra_ignore_patterns=["b.py"])
    assert result.ignored_file_count == 1
    assert result.inline_suppressed_count == 1
    assert result.findings == []


def test_db_connection_string_with_real_password_still_flagged(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('DATABASE_URL = "postgresql://app:Xk9mQ2vRfP7nL4wE@db.example.com:5432/prod"\n')
    findings = scan_file(str(f))
    kinds = {x.kind for x in findings}
    assert "db_connection_string_with_creds" in kinds


def test_db_connection_string_placeholder_password_not_flagged(tmp_path):
    """A .env.example / docker-compose template with a placeholder in the password slot
    (***, testpass, changeme, xxxx) is not a real leaked credential."""
    placeholders = [
        'DATABASE_URL=postgresql://devpilot:***@postgres:5432/devpilot',
        'DATABASE_URL: postgresql://devpilot:testpass@localhost:5432/devpilot_test',
        'DATABASE_URL=postgresql://user:changeme@db:5432/app',
        'DATABASE_URL=postgresql://user:xxxxxxxx@db:5432/app',
        'DATABASE_URL=postgresql://user:password@localhost:5432/devpilot',
    ]
    for i, line in enumerate(placeholders):
        f = tmp_path / f"placeholder_{i}.env"
        f.write_text(line + "\n")
        findings = scan_file(str(f))
        kinds = {x.kind for x in findings}
        assert "db_connection_string_with_creds" not in kinds, f"false positive on: {line}"


def test_private_key_header_with_real_body_still_flagged(tmp_path):
    f = tmp_path / "id_rsa.txt"
    f.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA1c7wJnEXAMPLEREALLOOKINGBASE64BODYNOTAPLACEHOLDERxyz\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    findings = scan_file(str(f))
    kinds = {x.kind for x in findings}
    assert "private_key_header" in kinds


def test_db_connection_string_env_var_reference_not_flagged(tmp_path):
    """DB_URL: postgresql://user:${DB_PASSWORD}@host/db is an interpolated env var,
    not a hardcoded credential — same class of false positive already fixed for
    generic_secret_assignment, found via self-testing against a real repo."""
    f = tmp_path / "docker-compose.yml"
    f.write_text('DB_CONNECTION_URI: postgresql://infisical:${INFISICAL_DB_PASSWORD}@db:5432/infisical\n')
    findings = scan_file(str(f))
    kinds = {x.kind for x in findings}
    assert "db_connection_string_with_creds" not in kinds


def test_private_key_header_placeholder_body_not_flagged(tmp_path):
    """A setup guide showing 'here's what a private key looks like' with '...' or
    'FAKE'/'PLACEHOLDER' as the body isn't an actually-committed key."""
    f = tmp_path / "SETUP.md"
    f.write_text(
        "GITHUB_PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\n"
        "...\n"
        "-----END RSA PRIVATE KEY-----\"\n"
    )
    findings = scan_file(str(f))
    kinds = {x.kind for x in findings}
    assert "private_key_header" not in kinds
