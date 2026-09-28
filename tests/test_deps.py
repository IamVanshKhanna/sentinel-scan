import os

import responses

from sentinel_scan.deps import (
    Dependency,
    compute_timeout,
    find_manifests,
    parse_requirements_txt,
    query_osv,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_parse_requirements_txt():
    deps = parse_requirements_txt(os.path.join(FIXTURES, "requirements.txt"))
    names = {d.name for d in deps}
    assert names == {"requests", "django", "flask"}
    assert all(d.ecosystem == "PyPI" for d in deps)


def test_find_manifests_walks_directory():
    deps = find_manifests(FIXTURES)
    assert any(d.name == "requests" for d in deps)


@responses.activate
def test_query_osv_returns_vuln_findings():
    dep = Dependency(name="requests", version="2.6.0", ecosystem="PyPI", manifest="requirements.txt")

    mock_response = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-fake-0000-0000",
                        "summary": "Fake vulnerability for testing",
                        "severity": [{"type": "CVSS_V3", "score": "9.5/10"}],
                    }
                ]
            }
        ]
    }
    responses.add(
        responses.POST,
        "https://api.osv.dev/v1/querybatch",
        json=mock_response,
        status=200,
    )

    result = query_osv([dep])
    assert result.ok is True
    assert len(result.findings) == 1
    assert result.findings[0].package == "requests"
    assert result.findings[0].vuln_id == "GHSA-fake-0000-0000"
    assert result.findings[0].severity == "critical"


@responses.activate
def test_query_osv_reports_not_ok_on_network_error():
    """A failed OSV query must be distinguishable from a clean result — empty findings
    alone is ambiguous between 'checked, found nothing' and 'never actually checked'."""
    dep = Dependency(name="requests", version="2.6.0", ecosystem="PyPI", manifest="requirements.txt")
    responses.add(responses.POST, "https://api.osv.dev/v1/querybatch", status=500)

    result = query_osv([dep])
    assert result.ok is False
    assert result.findings == []


def test_query_osv_empty_input_returns_ok_empty():
    result = query_osv([])
    assert result.ok is True
    assert result.findings == []


def test_compute_timeout_has_a_floor_for_small_batches():
    assert compute_timeout(0) == 15.0
    assert compute_timeout(1) == 15.0
    assert compute_timeout(10) == 15.0


def test_compute_timeout_scales_up_for_large_batches():
    """A fixed 15s timeout would deterministically fail on a large dependency batch —
    the effective timeout must grow with how many packages are being queried."""
    assert compute_timeout(200) == 50.0
    assert compute_timeout(1000) > compute_timeout(200)

@responses.activate
def test_query_osv_rejects_incomplete_batch():
    deps = [Dependency(name=n, version="1.0", ecosystem="PyPI", manifest="requirements.txt")
            for n in ("first", "second")]
    responses.add(responses.POST, "https://api.osv.dev/v1/querybatch",
                  json={"results": [{"vulns": []}]}, status=200)
    result = query_osv(deps)
    assert result.ok is False
    assert result.findings == []


@responses.activate
def test_query_osv_rejects_malformed_success_response():
    dep = Dependency(name="first", version="1.0", ecosystem="PyPI", manifest="requirements.txt")
    responses.add(responses.POST, "https://api.osv.dev/v1/querybatch",
                  json={"results": [{"vulns": "not a list"}]}, status=200)
    assert query_osv([dep]).ok is False
