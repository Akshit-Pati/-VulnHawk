"""
=========================================================
 VulnHawk Path Traversal Detection Engine
=========================================================

Purpose:
    Detect potential path traversal vulnerabilities in
    discovered URL parameters.

Detection approach:
    1. Use crawler-discovered parameter_map
    2. Establish a baseline response
    3. Send controlled traversal payloads
    4. Look for strong file-content indicators
    5. Compare response characteristics
    6. Return evidence-oriented findings

Active testing must only be performed against systems
you are authorized to assess.
"""

import requests

from urllib.parse import (
    urljoin,
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse,
)


class PathTraversalScanner:

    # =========================================================
    # CONFIGURATION
    # =========================================================

    TIMEOUT = 8

    MAX_PAYLOADS_PER_PARAMETER = 6

    MARKER = "VULNHAWK_PATH_TEST"

    # Controlled traversal payloads.
    PAYLOADS = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%2fpasswd",
        "..\\..\\..\\..\\Windows\\win.ini",
        "..%5c..%5c..%5c..%5cWindows%5cwin.ini",
        "....//....//....//....//etc/passwd",
    ]

    # Strong indicators of local file disclosure.
    UNIX_INDICATORS = [
        "root:x:0:0:",
        "root:*:0:0:",
        "daemon:x:",
        "bin:x:",
        "nobody:x:",
    ]

    WINDOWS_INDICATORS = [
        "[extensions]",
        "[fonts]",
        "[mci extensions]",
        "[files]",
        "for 16-bit app support",
    ]

    # =========================================================
    # HTTP SESSION
    # =========================================================

    @staticmethod
    def _session():

        session = requests.Session()

        session.headers.update({
            "User-Agent": "VulnHawk/1.0 Security Scanner"
        })

        return session

    # =========================================================
    # TARGET NORMALIZATION
    # =========================================================

    @staticmethod
    def normalize_target(target):

        if not target:
            return None

        target = str(target).strip()

        if not target.startswith(
            ("http://", "https://")
        ):
            target = "http://" + target

        parsed = urlparse(target)

        if not parsed.netloc:
            return None

        return urlunparse(
            (
                parsed.scheme.lower(),
                parsed.netloc,
                parsed.path or "/",
                "",
                parsed.query,
                "",
            )
        )

    # =========================================================
    # SAME-ORIGIN VALIDATION
    # =========================================================

    @staticmethod
    def is_in_scope(target, endpoint):

        try:

            target_parsed = urlparse(target)
            endpoint_parsed = urlparse(endpoint)

            target_scheme = (
                target_parsed.scheme.lower()
            )

            endpoint_scheme = (
                endpoint_parsed.scheme.lower()
            )

            target_host = (
                target_parsed.hostname or ""
            ).lower()

            endpoint_host = (
                endpoint_parsed.hostname or ""
            ).lower()

            target_port = (
                target_parsed.port
                or (
                    443
                    if target_scheme == "https"
                    else 80
                )
            )

            endpoint_port = (
                endpoint_parsed.port
                or (
                    443
                    if endpoint_scheme == "https"
                    else 80
                )
            )

            return (
                target_scheme == endpoint_scheme
                and target_host == endpoint_host
                and target_port == endpoint_port
            )

        except Exception:
            return False

    # =========================================================
    # BUILD TEST URL
    # =========================================================

    @staticmethod
    def build_test_url(
        endpoint,
        parameter,
        payload
    ):

        parsed = urlparse(endpoint)

        query_parameters = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        if not query_parameters:

            query_parameters = [
                (parameter, payload)
            ]

        else:

            replaced = False
            updated = []

            for key, value in query_parameters:

                if key == parameter:

                    updated.append(
                        (key, payload)
                    )

                    replaced = True

                else:

                    updated.append(
                        (key, value)
                    )

            if not replaced:

                updated.append(
                    (parameter, payload)
                )

            query_parameters = updated

        new_query = urlencode(
            query_parameters,
            doseq=True,
        )

        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                "",
            )
        )

    # =========================================================
    # HTTP REQUEST
    # =========================================================

    @classmethod
    def _request(
        cls,
        session,
        url
    ):

        try:

            response = session.get(
                url,
                timeout=cls.TIMEOUT,
                allow_redirects=True,
            )

            return {
                "success": True,
                "status_code": response.status_code,
                "text": response.text,
                "length": len(response.text),
                "final_url": response.url,
                "content_type": response.headers.get(
                    "Content-Type",
                    "",
                ),
            }

        except requests.RequestException as exc:

            return {
                "success": False,
                "error": str(exc),
                "status_code": None,
                "text": "",
                "length": 0,
                "final_url": url,
                "content_type": "",
            }

    # =========================================================
    # FILE CONTENT DETECTION
    # =========================================================

    @classmethod
    def detect_file_evidence(cls, text):

        if not text:
            return []

        normalized = str(text).lower()

        matched = []

        for indicator in cls.UNIX_INDICATORS:

            if indicator.lower() in normalized:

                matched.append({
                    "platform": "Unix/Linux",
                    "indicator": indicator,
                })

        for indicator in cls.WINDOWS_INDICATORS:

            if indicator.lower() in normalized:

                matched.append({
                    "platform": "Windows",
                    "indicator": indicator,
                })

        return matched

    # =========================================================
    # RESPONSE DIFFERENCE
    # =========================================================

    @staticmethod
    def response_changed(
        baseline,
        test
    ):

        if not baseline.get("success"):
            return False

        if not test.get("success"):
            return False

        status_changed = (
            baseline.get("status_code")
            != test.get("status_code")
        )

        baseline_length = baseline.get(
            "length",
            0,
        )

        test_length = test.get(
            "length",
            0,
        )

        if baseline_length == 0:

            length_difference = 0

        else:

            length_difference = (
                abs(
                    test_length
                    - baseline_length
                )
                / baseline_length
            )

        significant_length_change = (
            length_difference >= 0.30
        )

        return (
            status_changed
            or significant_length_change
        )

    # =========================================================
    # FINDING BUILDER
    # =========================================================

    @staticmethod
    def build_finding(
        endpoint,
        parameter,
        payload,
        evidence,
        confidence,
        platform,
    ):

        indicator_text = ", ".join(
            item.get("indicator", "")
            for item in evidence
        )

        return {
            "title": "Potential Path Traversal",
            "severity": "High",
            "confidence": confidence,
            "category": "Path Traversal",
            "type": "Evidence-Based Active Test",
            "affected_url": endpoint,
            "parameter": parameter,
            "payload": payload,
            "evidence": (
                "Traversal payload produced file-content "
                "indicators associated with "
                f"{platform}. "
                f"Matched indicators: {indicator_text}"
            ),
            "recommendation": (
                "Validate and canonicalize user-controlled "
                "file paths, restrict access to an approved "
                "directory, and prevent traversal outside "
                "the intended filesystem boundary."
            ),
            "cwe_id": "CWE-22",
            "cwe_name": (
                "Improper Limitation of a Pathname "
                "to a Restricted Directory"
            ),
        }

    # =========================================================
    # FINDING DEDUPLICATION
    # =========================================================

    @staticmethod
    def deduplicate_findings(findings):

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

        for finding in findings:

            key = (
                str(
                    finding.get(
                        "title",
                        "",
                    )
                ).lower(),

                str(
                    finding.get(
                        "affected_url",
                        "",
                    )
                ).lower(),

                str(
                    finding.get(
                        "parameter",
                        "",
                    )
                ).lower(),
            )

            if key not in unique:

                unique[key] = finding

                continue

            current = unique[key]

            current_severity = (
                severity_rank.get(
                    current.get(
                        "severity"
                    ),
                    0,
                )
            )

            new_severity = (
                severity_rank.get(
                    finding.get(
                        "severity"
                    ),
                    0,
                )
            )

            if new_severity > current_severity:

                current["severity"] = (
                    finding.get(
                        "severity"
                    )
                )

            current_confidence = (
                confidence_rank.get(
                    current.get(
                        "confidence"
                    ),
                    0,
                )
            )

            new_confidence = (
                confidence_rank.get(
                    finding.get(
                        "confidence"
                    ),
                    0,
                )
            )

            if new_confidence > current_confidence:

                current["confidence"] = (
                    finding.get(
                        "confidence"
                    )
                )

        return list(
            unique.values()
        )

    # =========================================================
    # MAIN SCANNER
    # =========================================================

    @classmethod
    def scan(
        cls,
        target,
        parameter_map,
    ):

        target = cls.normalize_target(
            target
        )

        result = {
            "target": target,
            "tested_parameters": [],
            "baseline": [],
            "evidence": [],
            "findings": [],
            "errors": [],
        }

        if not target:

            result["errors"].append(
                "Invalid target URL."
            )

            return result

        if not isinstance(
            parameter_map,
            dict,
        ):

            result["errors"].append(
                "Invalid parameter map."
            )

            return result

        session = cls._session()

        # =====================================================
        # DISCOVERED ENDPOINTS
        # =====================================================

        for endpoint_path, parameters in (
            parameter_map.items()
        ):

            if not parameters:
                continue

            endpoint = urljoin(
                target,
                endpoint_path,
            )

            if not cls.is_in_scope(
                target,
                endpoint,
            ):
                continue

            for parameter in parameters:

                if not parameter:
                    continue

                parameter = str(
                    parameter
                ).strip()

                if not parameter:
                    continue

                result[
                    "tested_parameters"
                ].append({
                    "endpoint": endpoint_path,
                    "parameter": parameter,
                })

                # =================================================
                # BASELINE REQUEST
                # =================================================

                baseline_url = (
                    cls.build_test_url(
                        endpoint,
                        parameter,
                        cls.MARKER,
                    )
                )

                if not cls.is_in_scope(
                    target,
                    baseline_url,
                ):
                    continue

                baseline = cls._request(
                    session,
                    baseline_url,
                )

                if not baseline.get(
                    "success"
                ):

                    result["errors"].append({
                        "endpoint": endpoint_path,
                        "parameter": parameter,
                        "error": baseline.get(
                            "error",
                            "Baseline request failed.",
                        ),
                    })

                    continue

                result["baseline"].append({
                    "endpoint": endpoint_path,
                    "parameter": parameter,
                    "status_code": baseline.get(
                        "status_code"
                    ),
                    "response_length": baseline.get(
                        "length"
                    ),
                })

                # =================================================
                # PAYLOAD TESTING
                # =================================================

                payloads = cls.PAYLOADS[
                    :cls.MAX_PAYLOADS_PER_PARAMETER
                ]

                for payload in payloads:

                    test_url = (
                        cls.build_test_url(
                            endpoint,
                            parameter,
                            payload,
                        )
                    )

                    if not cls.is_in_scope(
                        target,
                        test_url,
                    ):
                        continue

                    test = cls._request(
                        session,
                        test_url,
                    )

                    if not test.get(
                        "success"
                    ):
                        continue

                    evidence = (
                        cls.detect_file_evidence(
                            test.get(
                                "text",
                                "",
                            )
                        )
                    )

                    response_changed = (
                        cls.response_changed(
                            baseline,
                            test,
                        )
                    )

                    # =================================================
                    # STRONG EVIDENCE
                    # =================================================

                    if evidence:

                        platform = (
                            evidence[0].get(
                                "platform",
                                "Unknown",
                            )
                        )

                        finding = (
                            cls.build_finding(
                                endpoint,
                                parameter,
                                payload,
                                evidence,
                                "High",
                                platform,
                            )
                        )

                        finding["response"] = {
                            "baseline_status": (
                                baseline.get(
                                    "status_code"
                                )
                            ),
                            "test_status": (
                                test.get(
                                    "status_code"
                                )
                            ),
                            "baseline_length": (
                                baseline.get(
                                    "length"
                                )
                            ),
                            "test_length": (
                                test.get(
                                    "length"
                                )
                            ),
                            "response_changed": (
                                response_changed
                            ),
                        }

                        result[
                            "evidence"
                        ].append({
                            "endpoint": endpoint_path,
                            "parameter": parameter,
                            "payload": payload,
                            "platform": platform,
                            "indicators": evidence,
                        })

                        result[
                            "findings"
                        ].append(
                            finding
                        )

                        # Strong evidence found.
                        break

        # =========================================================
        # FINAL DEDUPLICATION
        # =========================================================

        result["findings"] = (
            cls.deduplicate_findings(
                result["findings"]
            )
        )

        return result


# =============================================================
# BACKWARD COMPATIBILITY
# =============================================================

PathTraversal = PathTraversalScanner