"""
VulnHawk - Finding Metadata Engine

Provides standardized metadata for vulnerability findings:
- CWE identification
- CWE names
- CVSS version
- CVSS vector
- CVSS score metadata
- vulnerability category

Important:
CVSS scores are not invented for configuration observations.
When a finding does not have enough evidence for a defensible CVSS
assessment, the CVSS score/vector remains None.
"""

from typing import Any, Dict, Optional


class FindingMetadata:

    # ============================================================
    # STANDARD VULNERABILITY METADATA
    # ============================================================

    FINDING_METADATA = {

        # --------------------------------------------------------
        # CROSS-SITE SCRIPTING
        # --------------------------------------------------------

        "cross-site scripting": {
            "cwe_id": "CWE-79",
            "cwe_name": "Improper Neutralization of Input During Web Page Generation",
            "category": "Injection",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        "reflected xss": {
            "cwe_id": "CWE-79",
            "cwe_name": "Improper Neutralization of Input During Web Page Generation",
            "category": "Injection",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        "potential reflected xss sink": {
            "cwe_id": "CWE-79",
            "cwe_name": "Improper Neutralization of Input During Web Page Generation",
            "category": "Injection",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
            "impact": (
                "Untrusted input was observed being reflected in the web response. "
                "Depending on the output context and browser behavior, reflected "
                "input may create a client-side injection risk."
            ),
            "recommendation": (
                "Apply context-aware output encoding for untrusted data before "
                "rendering it in the response. Validate and constrain user input "
                "where appropriate, and avoid inserting untrusted data into "
                "executable browser contexts."
            ),
        },

        # --------------------------------------------------------
        # SQL INJECTION
        # --------------------------------------------------------

        "sql injection": {
            "cwe_id": "CWE-89",
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
            "category": "Injection",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        "potential sql injection": {
            "cwe_id": "CWE-89",
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
            "category": "Injection",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
            "impact": (
                "The tested input produced response behavior associated with "
                "SQL injection indicators. If exploitable, insufficiently "
                "protected database queries could allow unintended database "
                "operations or disclosure of application data."
            ),
            "recommendation": (
                "Use parameterized queries or prepared statements for database "
                "operations. Avoid constructing SQL statements through direct "
                "concatenation of untrusted input and apply appropriate server-side "
                "input validation."
             ),
        },

        "sql injection indicator": {
            "cwe_id": "CWE-89",
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
            "category": "Injection",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        # --------------------------------------------------------
        # PATH TRAVERSAL
        # --------------------------------------------------------

        "path traversal": {
            "cwe_id": "CWE-22",
            "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory",
            "category": "Path Traversal",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
            "impact": (
                "If exploitable, insufficient restriction of file paths could "
                "allow an attacker to access files outside the intended application "
                "directory."
            ),
            "recommendation": (
                "Restrict file access to approved directories, normalize and "
                "validate file paths, reject traversal sequences, and use "
                "allowlisted file identifiers instead of directly accepting "
                "filesystem paths from untrusted input."
            ),
        },

        "directory traversal": {
            "cwe_id": "CWE-22",
            "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory",
            "category": "Path Traversal",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        # --------------------------------------------------------
        # OPEN REDIRECT
        # --------------------------------------------------------

        "open redirect": {
            "cwe_id": "CWE-601",
            "cwe_name": "URL Redirection to Untrusted Site",
            "category": "Redirect",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
            "impact": (
                "An unvalidated redirect destination may allow an attacker to "
                "redirect users from a trusted application URL to an external "
                "destination."
            ),
            "recommendation": (
                "Validate redirect destinations against an allowlist of trusted "
                "paths or domains. Prefer server-side route identifiers over "
                "user-controlled absolute URLs and reject untrusted external "
                "destinations."
            ),
        },

        "url redirection": {
            "cwe_id": "CWE-601",
            "cwe_name": "URL Redirection to Untrusted Site",
            "category": "Redirect",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        # --------------------------------------------------------
        # CSRF
        # --------------------------------------------------------

        "cross-site request forgery": {
            "cwe_id": "CWE-352",
            "cwe_name": "Cross-Site Request Forgery",
            "category": "Session / Request Integrity",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        "csrf": {
            "cwe_id": "CWE-352",
            "cwe_name": "Cross-Site Request Forgery",
            "category": "Session / Request Integrity",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        # --------------------------------------------------------
        # CLICKJACKING
        # --------------------------------------------------------

        "clickjacking": {
            "cwe_id": "CWE-1021",
            "cwe_name": "Improper Restriction of Rendered UI Layers or Frames",
            "category": "Browser Security",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        # --------------------------------------------------------
        # CORS
        # --------------------------------------------------------

        "cors misconfiguration": {
            "cwe_id": "CWE-942",
            "cwe_name": "Permissive Cross-domain Policy with Untrusted Domains",
            "category": "Configuration",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        "cors": {
            "cwe_id": "CWE-942",
            "cwe_name": "Permissive Cross-domain Policy with Untrusted Domains",
            "category": "Configuration",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        # --------------------------------------------------------
        # SECURITY HEADERS
        # --------------------------------------------------------
        # These are intentionally not assigned a generic CWE.
        # Missing headers are configuration observations and their
        # real security impact depends on the application context.

"missing content-security-policy": {
    "cwe_id": None,
    "cwe_name": None,
    "category": "Security Headers",
    "cvss_version": None,
    "cvss_score": None,
    "cvss_vector": None,

    "description": (
        "The target is missing the Content-Security-Policy "
        "HTTP security header."
    ),

    "impact": (
        "Without a suitable Content-Security-Policy, the "
        "application may have reduced protection against "
        "certain client-side injection attacks."
    ),

    "recommendation": (
        "Configure an appropriate Content-Security-Policy "
        "header based on the application's required resources "
        "and trusted sources."
    ),
},

        "missing strict-transport-security": {
    "cwe_id": None,
    "cwe_name": None,
    "category": "Security Headers",
    "cvss_version": None,
    "cvss_score": None,
    "cvss_vector": None,

    "description": (
        "The target is missing the Strict-Transport-Security "
        "security header."
    ),

    "impact": (
        "The browser may not be instructed to always use HTTPS "
        "for future connections to the target."
    ),

    "recommendation": (
        "Configure the Strict-Transport-Security header with "
        "an appropriate max-age value and HTTPS configuration."
    ),
},

        "missing x-content-type-options": {
    "cwe_id": None,
    "cwe_name": None,
    "category": "Security Headers",
    "cvss_version": None,
    "cvss_score": None,
    "cvss_vector": None,

    "description": (
        "The target is missing the X-Content-Type-Options "
        "security header."
    ),

    "impact": (
        "Browsers may have fewer restrictions against MIME "
        "type sniffing."
    ),

    "recommendation": (
        "Set X-Content-Type-Options to nosniff."
    ),
},

        "missing x-frame-options": {
    "cwe_id": None,
    "cwe_name": None,
    "category": "Security Headers",
    "cvss_version": None,
    "cvss_score": None,
    "cvss_vector": None,

    "description": (
        "The target is missing the X-Frame-Options "
        "security header."
    ),

    "impact": (
        "The application may have reduced protection against "
        "unwanted framing by other websites."
    ),

    "recommendation": (
        "Configure an appropriate X-Frame-Options policy such "
        "as SAMEORIGIN where applicable."
    ),
},
       "missing referrer-policy": {
    "cwe_id": None,
    "cwe_name": None,
    "category": "Security Headers",
    "cvss_version": None,
    "cvss_score": None,
    "cvss_vector": None,

    "description": (
        "The target is missing the Referrer-Policy "
        "security header."
    ),

    "impact": (
        "More referrer information than necessary may "
        "potentially be exposed when navigating from the application."
    ),

    "recommendation": (
        "Configure a Referrer-Policy appropriate for the "
        "application's privacy and functionality requirements."
    ),
},

        "missing permissions-policy": {
    "cwe_id": None,
    "cwe_name": None,
    "category": "Security Headers",
    "cvss_version": None,
    "cvss_score": None,
    "cvss_vector": None,

    "description": (
        "The target is missing the Permissions-Policy "
        "security header."
    ),

    "impact": (
        "The application does not explicitly define browser "
        "feature permissions through this header."
    ),

    "recommendation": (
        "Configure Permissions-Policy to restrict browser "
        "features that the application does not require."
    ),
},

        # --------------------------------------------------------
        # SSL / TLS
        # --------------------------------------------------------

        "certificate error": {
            "cwe_id": "CWE-295",
            "cwe_name": "Improper Certificate Validation",
            "category": "Cryptographic / TLS",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        "invalid certificate": {
            "cwe_id": "CWE-295",
            "cwe_name": "Improper Certificate Validation",
            "category": "Cryptographic / TLS",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        # --------------------------------------------------------
        # INFORMATION DISCLOSURE
        # --------------------------------------------------------

        "information disclosure": {
            "cwe_id": "CWE-200",
            "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
            "category": "Information Disclosure",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        # --------------------------------------------------------
        # DIRECTORY LISTING
        # --------------------------------------------------------

        "directory listing": {
            "cwe_id": "CWE-548",
            "cwe_name": "Exposure of Information Through Directory Listing",
            "category": "Information Disclosure",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        # --------------------------------------------------------
        # COMMAND INJECTION
        # --------------------------------------------------------

        "command injection": {
            "cwe_id": "CWE-78",
            "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
            "category": "Injection",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        # --------------------------------------------------------
        # SERVER-SIDE REQUEST FORGERY
        # --------------------------------------------------------

        "server-side request forgery": {
            "cwe_id": "CWE-918",
            "cwe_name": "Server-Side Request Forgery",
            "category": "Server-Side Request Forgery",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },

        "ssrf": {
            "cwe_id": "CWE-918",
            "cwe_name": "Server-Side Request Forgery",
            "category": "Server-Side Request Forgery",
            "cvss_version": "4.0",
            "cvss_score": None,
            "cvss_vector": None,
        },
    }

    # ============================================================
    # NORMALIZE FINDING TITLE
    # ============================================================

    @staticmethod
    def normalize_title(title: Any) -> str:
        if not title:
            return ""

        return (
            str(title)
            .strip()
            .lower()
            .replace("_", " ")
            .replace("-", " ")
        )

    # ============================================================
    # FIND EXACT / PARTIAL METADATA
    # ============================================================

    @classmethod
    def get_metadata(cls, title: Any) -> Dict[str, Any]:

        normalized_title = cls.normalize_title(title)

        if not normalized_title:
            return cls.default_metadata()

        # Exact match
        if normalized_title in cls.FINDING_METADATA:
            return dict(cls.FINDING_METADATA[normalized_title])

        # Partial match
        for finding_name, metadata in cls.FINDING_METADATA.items():

            if finding_name in normalized_title:
                return dict(metadata)

            if normalized_title in finding_name:
                return dict(metadata)

        return cls.default_metadata()

    # ============================================================
    # DEFAULT METADATA
    # ============================================================

    @staticmethod
    def default_metadata() -> Dict[str, Any]:

        return {
            "cwe_id": None,
            "cwe_name": None,
            "category": "Unclassified",
            "cvss_version": None,
            "cvss_score": None,
            "cvss_vector": None,
        }

    # ============================================================
    # ENRICH ONE FINDING
    # ============================================================

    @classmethod
    def enrich_finding(
        cls,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:

        if not isinstance(finding, dict):
            return finding

        enriched = dict(finding)

        metadata = cls.get_metadata(
            finding.get("title", "")
        )

        # Do not overwrite manually supplied values.
        enriched.setdefault(
            "cwe_id",
            metadata.get("cwe_id")
        )

        enriched.setdefault(
            "cwe_name",
            metadata.get("cwe_name")
        )

        enriched.setdefault(
            "cvss_version",
            metadata.get("cvss_version")
        )

        enriched.setdefault(
            "cvss_score",
            metadata.get("cvss_score")
        )

        enriched.setdefault(
            "cvss_vector",
            metadata.get("cvss_vector")
        )

        enriched.setdefault(
            "description",
            metadata.get("description")
        )

        enriched.setdefault(
            "impact",
            metadata.get("impact")
        )

        enriched.setdefault(
            "recommendation",
            metadata.get("recommendation")
        )

        if not enriched.get("category"):
            enriched["category"] = metadata.get(
                "category",
                "Unclassified"
            )

        return enriched

    # ============================================================
    # ENRICH ALL FINDINGS
    # ============================================================

    @classmethod
    def enrich_findings(
        cls,
        findings: Any
    ) -> list:

        if not isinstance(findings, list):
            return []

        return [
            cls.enrich_finding(finding)
            for finding in findings
            if isinstance(finding, dict)
        ]