from secureflow.reporting.normalizer import (
     normalize_semgrep, 
     normalize_osv, 
     normalize_gitleaks, 
     normalize_zap
)


def test_normalize_semgrep():
    data = {
        "results": [
            {
                "check_id": "python.security.sql-injection",
                "path": "/src/app.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Potential SQL Injection",
                    "severity": "ERROR",
                },
            }
        ]
    }

    findings = normalize_semgrep(data)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.scanner == "semgrep"
    assert finding.title == "Potential SQL Injection"
    assert finding.severity == "high"
    assert finding.location == "/src/app.py:42"
    assert finding.rule_id == "python.security.sql-injection"


def test_normalize_semgrep_empty_results():
    findings = normalize_semgrep({"results": []})

    assert findings == []


def test_normalize_semgrep_unknown_severity():
    data = {
        "results": [
            {
                "check_id": "test-rule",
                "path": "app.py",
                "start": {"line": 10},
                "extra": {
                    "message": "Test finding",
                    "severity": "UNKNOWN",
                },
            }
        ]
    }

    findings = normalize_semgrep(data)

    assert findings[0].severity == "unknown"


def test_normalize_osv():
    data = {
        "results": [
            {
                "source": {"path": "/src/package-lock.json"},
                "packages": [
                    {
                        "package": {
                            "name": "example-package",
                            "version": "1.2.3",
                            "ecosystem": "npm",
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-1234-5678-abcd",
                                "summary": "Example vulnerability",
                            },
                            {
                                "id": "GHSA-9876-5432-dcba",
                                "summary": "Another vulnerability",
                            },
                        ],
                    }
                ],
            }
        ]
    }

    findings = normalize_osv(data)

    assert len(findings) == 2

    assert findings[0].scanner == "osv"
    assert findings[0].title == "example-package@1.2.3: GHSA-1234-5678-abcd"
    assert findings[0].severity == "unknown"
    assert findings[0].description == "Example vulnerability"
    assert findings[0].location == "/src/package-lock.json"
    assert findings[0].rule_id == "GHSA-1234-5678-abcd"
    assert findings[0].reference == (
        "https://osv.dev/vulnerability/GHSA-1234-5678-abcd"
    )


def test_normalize_osv_empty_results():
    assert normalize_osv({"results": []}) == []


def test_normalize_osv_missing_vulnerability_id():
    data = {
        "results": [
            {
                "source": {"path": "package-lock.json"},
                "packages": [
                    {
                        "package": {"name": "example", "version": "1.0"},
                        "vulnerabilities": [
                            {"summary": "Missing vulnerability ID"}
                        ],
                    }
                ],
            }
        ]
    }

    assert normalize_osv(data) == []



def test_normalize_gitleaks():
    data = [
        {
            "Description": "Generic API Key",
            "File": "src/config.py",
            "StartLine": 12,
            "RuleID": "generic-api-key",
            "Secret": "SHOULD_NOT_APPEAR",
        }
    ]

    findings = normalize_gitleaks(data)

    assert len(findings) == 1
    assert findings[0].scanner == "gitleaks"
    assert findings[0].severity == "high"
    assert findings[0].location == "src/config.py:12"
    assert findings[0].rule_id == "generic-api-key"

    # Never expose detected secrets in normalized findings.
    assert "SHOULD_NOT_APPEAR" not in findings[0].model_dump_json()


def test_normalize_gitleaks_empty():
    assert normalize_gitleaks([]) == []


def test_normalize_zap():
    data = {
        "site": [
            {
                "alerts": [
                    {
                        "name": "Content Security Policy (CSP) Header Not Set",
                        "riskcode": "2",
                        "desc": "CSP header is missing.",
                        "alertRef": "10038-1",
                        "instances": [
                            {"uri": "http://127.0.0.1:3000/"}
                        ],
                    }
                ]
            }
        ]
    }

    findings = normalize_zap(data)

    assert len(findings) == 1
    assert findings[0].scanner == "zap"
    assert findings[0].severity == "medium"
    assert findings[0].rule_id == "10038-1"
    assert findings[0].location == "http://127.0.0.1:3000/"


def test_normalize_zap_empty():
    assert normalize_zap({"site": []}) == []


def test_normalize_zap_unknown_severity():
    data = {
        "site": [
            {
                "alerts": [
                    {
                        "name": "Unknown alert",
                        "riskcode": "99",
                    }
                ]
            }
        ]
    }

    findings = normalize_zap(data)

    assert findings[0].severity == "unknown"
