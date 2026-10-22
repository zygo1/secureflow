from secureflow.reporting.models import SecurityFinding
from secureflow.reporting.severity import cvss_vector_to_severity
import re
from html import unescape

def normalize_semgrep(data: dict) -> list[SecurityFinding]:
    findings = []

    severity_map = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
    }

    for result in data.get("results", []):
        extra = result.get("extra", {})

        message = extra.get("message", "Unknown finding")
        severity = severity_map.get(
            extra.get("severity", "").upper(),
            "unknown",
        )

        path = result.get("path")
        line = result.get("start", {}).get("line")

        location = (
            f"{path}:{line}"
            if path and line is not None
            else path
        )

        finding = SecurityFinding(
            scanner="semgrep",
            title=message,
            severity=severity,
            description=message,
            location=location,
            rule_id=result.get("check_id"),
        )

        findings.append(finding)

    return findings


def normalize_osv(data: dict) -> list[SecurityFinding]:
    findings = []

    for result in data.get("results", []):
        source = result.get("source", {})
        source_path = source.get("path")

        for entry in result.get("packages", []):
            package = entry.get("package", {})

            name = package.get("name", "unknown")
            version = package.get("version", "unknown")

            for vulnerability in entry.get("vulnerabilities", []):
                vuln_id = vulnerability.get("id")

                if not vuln_id:
                    continue

                summary = vulnerability.get("summary")
                details = vulnerability.get("details")

                severity = "unknown"

                for severity_entry in vulnerability.get("severity", []):
                    vector = severity_entry.get("score", "")

                    calculated_severity = cvss_vector_to_severity(vector)

                    if calculated_severity != "unknown":
                        severity = calculated_severity
                        break

                finding = SecurityFinding(
                    scanner="osv",
                    title=f"{name}@{version}: {vuln_id}",
                    severity=severity,
                    description=summary or details or "",
                    location=source_path,
                    rule_id=vuln_id,
                    reference=f"https://osv.dev/vulnerability/{vuln_id}",
                )

                findings.append(finding)

    return findings



def normalize_gitleaks(data: list[dict]) -> list[SecurityFinding]:
    findings = []

    for result in data:
        description = result.get("Description") or "Potential exposed secret"
        path = result.get("File")
        line = result.get("StartLine")

        location = (
            f"{path}:{line}"
            if path and line is not None
            else path
        )

        finding = SecurityFinding(
            scanner="gitleaks",
            title=description,
            severity="high",
            description="Potential secret detected in source code.",
            location=location,
            rule_id=result.get("RuleID"),
        )

        findings.append(finding)

    return findings


def clean_zap_html(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", value)
    text = unescape(text)
    return " ".join(text.split())


def normalize_zap(data: dict) -> list[SecurityFinding]:
    findings = []

    severity_map = {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
    }

    sites = data.get("site", [])

    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        for alert in site.get("alerts", []):
            riskcode = str(alert.get("riskcode", ""))

            severity = severity_map.get(riskcode, "unknown")

            name = alert.get("name") or alert.get("alert") or "Unknown ZAP alert"

            instances = alert.get("instances", [])
            location = None

            if instances:
                location = instances[0].get("uri")

            finding = SecurityFinding(
                scanner="zap",
                title=name,
                severity=severity,
                description=clean_zap_html(alert.get("desc") or ""),
                location=location,
                rule_id=str(alert.get("alertRef") or alert.get("pluginid") or "") or None,
                reference=clean_zap_html(alert.get("reference") or "") or None,
            )

            findings.append(finding)

    return findings

