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

    findings = query_osv([dep])
    assert len(findings) == 1
    assert findings[0].package == "requests"
    assert findings[0].vuln_id == "GHSA-fake-0000-0000"
    assert findings[0].severity == "critical"


@responses.activate
def test_query_osv_fails_soft_on_network_error():
    dep = Dependency(name="requests", version="2.6.0", ecosystem="PyPI", manifest="requirements.txt")
    responses.add(responses.POST, "https://api.osv.dev/v1/querybatch", status=500)

    findings = query_osv([dep])
    assert findings == []


def test_query_osv_empty_input_returns_empty():
    assert query_osv([]) == []
