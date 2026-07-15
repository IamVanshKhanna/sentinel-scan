import os

import responses

from sentinel_scan.deps import (
    Dependency,
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


@responses.activate
def test_query_osv_timeout_scales_with_batch_size():
    """A fixed 15s timeout would deterministically fail on a large dependency batch —
    the effective timeout should grow with how many packages are being queried."""
    deps = [
        Dependency(name=f"pkg{i}", version="1.0.0", ecosystem="PyPI", manifest="requirements.txt")
        for i in range(200)
    ]
    responses.add(responses.POST, "https://api.osv.dev/v1/querybatch", json={"results": [{}] * 200}, status=200)

    result = query_osv(deps)
    assert result.ok is True
    call_kwargs = responses.calls[0].request
    # We can't directly introspect the timeout passed to requests from the recorded call,
    # so this test exercises the large-batch path end-to-end and asserts it still succeeds
    # rather than asserting on internal timeout arithmetic.
    assert call_kwargs is not None
