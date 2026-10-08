
"""
=========================================================
 VulnHawk Security Score & Evidence Engine V1
=========================================================
"""

from scanner.finding_metadata import FindingMetadata

class SecurityScore:

    HEADER_RULES = {
        "Content-Security-Policy": {
    "severity": "Low",
    "recommendation": "Implement an appropriate Content-Security-Policy.",
    "impact": (
        "Without a suitable Content-Security-Policy, the "
        "application may have reduced protection against "
        "certain client-side injection attacks."
    )
},
        "Strict-Transport-Security": {
    "severity": "Low",
    "recommendation": "Consider enabling HSTS after confirming HTTPS readiness.",
    "impact": (
        "The browser may not be instructed to always use HTTPS "
        "for future connections to the target."
    )
},
        "X-Content-Type-Options": {
    "severity": "Low",
    "recommendation": "Set X-Content-Type-Options to nosniff.",
    "impact": (
        "Browsers may have fewer restrictions against MIME "
        "type sniffing."
    )
},
        "X-Frame-Options": {
    "severity": "Low",
    "recommendation": "Configure suitable anti-framing protection using CSP frame-ancestors or X-Frame-Options.",
    "impact": (
        "The application may have reduced protection against "
        "unwanted framing by other websites."
    )
},
        "Referrer-Policy": {
    "severity": "Info",
    "recommendation": "Define an appropriate Referrer-Policy.",
    "impact": (
        "More referrer information than necessary may potentially "
        "be exposed when navigating from the application."
    )
},
        "Permissions-Policy": {
    "severity": "Info",
    "recommendation": "Restrict unnecessary browser capabilities.",
    "impact": (
        "The application does not explicitly define browser "
        "feature permissions through this header."
    )
}
    }

    @staticmethod
    def _normalize_finding(finding, target):
        """Return a stable finding record with a deterministic dedup key."""

        finding = dict(finding or {})

        title = str(
            finding.get("title", "Unknown Finding")
        ).strip()

        severity = str(
            finding.get("severity", "Info")
        ).strip()

        category = str(
            finding.get("category", "General")
        ).strip()

        affected_url = str(
            finding.get("affected_url")
            or finding.get("url")
            or target
        ).strip()

        parameter = str(
            finding.get("parameter")
            or finding.get("param")
            or ""
        ).strip()

        finding["title"] = title
        finding["severity"] = severity
        finding["category"] = category
        finding["affected_url"] = affected_url

        if parameter:
            finding["parameter"] = parameter

        key = "|".join(
            [
                title.lower(),
                category.lower(),
                affected_url.lower(),
                parameter.lower(),
            ]
        )

        finding["_dedup_key"] = key
        return finding

    @staticmethod
    def deduplicate_findings(findings, target="Unknown"):
        """Deduplicate equivalent findings while preserving stronger evidence."""

        unique = {}

        severity_rank = {
            "Critical": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2,
            "Info": 1,
        }

        confidence_rank = {
            "High": 3,
            "Medium": 2,
            "Low": 1,
        }

        for raw_finding in findings or []:

            finding = SecurityScore._normalize_finding(
                raw_finding,
                target
            )

            key = finding["_dedup_key"]
            existing = unique.get(key)

            if existing is None:
                unique[key] = finding
                continue

            if (
                severity_rank.get(finding.get("severity"), 0)
                >
                severity_rank.get(existing.get("severity"), 0)
            ):
                existing["severity"] = finding["severity"]

            if (
                confidence_rank.get(finding.get("confidence"), 0)
                >
                confidence_rank.get(existing.get("confidence"), 0)
            ):
                existing["confidence"] = finding["confidence"]

            for field in (
                "evidence",
                "recommendation",
                "type",
                "cwe",
                "cvss",
            ):
                if (
                    not existing.get(field)
                    and finding.get(field)
                ):
                    existing[field] = finding[field]

        cleaned = []

        for finding in unique.values():
            finding.pop("_dedup_key", None)
            cleaned.append(finding)

        return cleaned

    @staticmethod
    def calculate(results):

        score = 100
        findings = []

        target = results.get("target", "Unknown")

        # =============================================
        # Security Headers
        # =============================================

        headers = results.get("headers", {})

        if isinstance(headers, dict) and "Error" not in headers:

            for header, status in headers.items():

                if status != "Missing":
                    continue

                rule = SecurityScore.HEADER_RULES.get(header)

                if not rule:
                    continue

                # HSTS is meaningful only when HTTPS is in use.
                # Do not report missing HSTS for HTTP-only targets.
                if (
                    header == "Strict-Transport-Security"
                    and not target.lower().startswith("https://")
                ):
                    continue

                severity = rule["severity"]

                # Preliminary heuristic scoring
                deduction = 2 if severity == "Low" else 0

                score -= deduction

                findings.append({
    "title": f"Missing {header}",
    "severity": severity,
    "confidence": "High",
    "category": "Security Headers",
    "type": "Configuration Observation",
    "affected_url": target,

    "description": (
        f"The target is missing the {header} "
        "HTTP security header."
    ),

    "impact": rule.get(
        "impact",
        "The absence of this security control may reduce "
        "the application's security protections."
    ),

    "evidence": (
        f"{header} was not present in the inspected "
        "HTTP response."
    ),

    "recommendation": rule["recommendation"]
})

        # =============================================
        # SSL / TLS
        # =============================================

        ssl_result = results.get("ssl", {})

        if isinstance(ssl_result, dict):

            ssl_status = ssl_result.get("Status")

            if ssl_status == "Certificate Error":

                score -= 10

                findings.append({
                    "title": "SSL/TLS Certificate Validation Failed",
                    "severity": "Medium",
                    "confidence": "High",
                    "category": "SSL/TLS",
                    "type": "Validation Failure",
                    "affected_url": target,
                    "evidence": ssl_result.get(
                        "Error",
                        "TLS certificate validation failed."
                    ),
                    "recommendation": (
                        "Inspect the TLS certificate, hostname, "
                        "trust chain and certificate configuration."
                    )
                })

            elif ssl_status == "Unavailable":

                findings.append({
                    "title": "HTTPS Service Unavailable",
                    "severity": "Info",
                    "confidence": "Medium",
                    "category": "SSL/TLS",
                    "type": "Availability Observation",
                    "affected_url": target,
                    "evidence": ssl_result.get(
                        "Error",
                        "HTTPS service could not be verified."
                    ),
                    "recommendation": (
                        "Verify that HTTPS is available and "
                        "reachable on the expected port."
                    )
                })

            elif ssl_status == "Not Applicable":

                # HTTP target — TLS testing does not apply.
                pass
        # =============================================
        # Finding Deduplication
        # =============================================
        #
        # Normalize and deduplicate findings from all
        # scanner modules before reporting.
        # =============================================

        findings = SecurityScore.deduplicate_findings(
            findings,
            target
        )

        findings = FindingMetadata.enrich_findings(
    findings
        )

        # =============================================
        # Score Limits
        # =============================================

        score = max(0, min(100, score))

        # =============================================
        # Rating
        # =============================================

        if score >= 90:
            rating = "Excellent"
        elif score >= 75:
            rating = "Good"
        elif score >= 50:
            rating = "Moderate"
        elif score >= 25:
            rating = "Poor"
        else:
            rating = "Critical"

        return {
            "score": score,
            "rating": rating,
            "findings": findings
        }