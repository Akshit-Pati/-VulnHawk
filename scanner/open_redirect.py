"""
=========================================================
 VulnHawk Open Redirect Detection Engine
=========================================================

Purpose:
    Detect potential open redirect vulnerabilities in
    discovered URL parameters.

Detection approach:
    1. Use crawler-discovered parameter_map
    2. Establish a baseline response
    3. Inject controlled external redirect targets
    4. Inspect HTTP Location headers and final destinations
    5. Verify that the redirect leaves the target origin
    6. Report only evidence-based findings

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


class OpenRedirectScanner:

    # =========================================================
    # CONFIGURATION
    # =========================================================

    TIMEOUT = 8

    MAX_PAYLOADS_PER_PARAMETER = 4

    TEST_HOST = "https://vulnhawk.invalid"

    PAYLOADS = [
        TEST_HOST,
        TEST_HOST + "/",
        "//vulnhawk.invalid/",
        "https://vulnhawk.invalid/redirect",
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
    def is_same_origin(
        target,
        endpoint
    ):

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
        url,
        allow_redirects=False
    ):

        try:

            response = session.get(
                url,
                timeout=cls.TIMEOUT,
                allow_redirects=allow_redirects,
            )

            return {
                "success": True,
                "status_code": response.status_code,
                "location": response.headers.get(
                    "Location"
                ),
                "final_url": response.url,
                "length": len(response.text),
                "text": response.text,
            }

        except requests.RequestException as exc:

            return {
                "success": False,
                "error": str(exc),
                "status_code": None,
                "location": None,
                "final_url": url,
                "length": 0,
                "text": "",
            }

    # =========================================================
    # EXTERNAL DESTINATION CHECK
    # =========================================================

    @classmethod
    def is_external_destination(
        cls,
        target,
        destination
    ):

        if not destination:
            return False

        try:

            absolute_destination = urljoin(
                target,
                destination
            )

            return not cls.is_same_origin(
                target,
                absolute_destination
            )

        except Exception:
            return False

    # =========================================================
    # FINDING BUILDER
    # =========================================================

    @staticmethod
    def build_finding(
        endpoint,
        parameter,
        payload,
        location,
        final_url
    ):

        return {
            "title": "Potential Open Redirect",
            "severity": "Medium",
            "confidence": "High",
            "category": "Redirect",
            "type": "Evidence-Based Active Test",
            "affected_url": endpoint,
            "parameter": parameter,
            "payload": payload,
            "evidence": (
                "The supplied redirect parameter caused the "
                "application to return an external Location "
                "destination."
            ),
            "redirect_location": location,
            "final_url": final_url,
            "recommendation": (
                "Validate redirect destinations against an "
                "allowlist of trusted paths or origins. "
                "Avoid directly redirecting to user-controlled "
                "external URLs."
            ),
            "cwe_id": "CWE-601",
            "cwe_name": (
                "URL Redirection to Untrusted Site"
            ),
        }

    # =========================================================
    # DEDUPLICATION
    # =========================================================

    @staticmethod
    def deduplicate_findings(
        findings
    ):

        unique = {}

        for finding in findings:

            key = (
                str(
                    finding.get(
                        "title",
                        ""
                    )
                ).lower(),

                str(
                    finding.get(
                        "affected_url",
                        ""
                    )
                ).lower(),

                str(
                    finding.get(
                        "parameter",
                        ""
                    )
                ).lower(),
            )

            if key not in unique:

                unique[key] = finding

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
        parameter_map
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
            dict
        ):

            result["errors"].append(
                "Invalid parameter map."
            )

            return result

        session = cls._session()

        # =====================================================
        # PROCESS DISCOVERED ENDPOINTS
        # =====================================================

        for endpoint_path, parameters in (
            parameter_map.items()
        ):

            if not parameters:
                continue

            endpoint = urljoin(
                target,
                endpoint_path
            )

            # Only test endpoints belonging to
            # the supplied target origin.
            if not cls.is_same_origin(
                target,
                endpoint
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
                # BASELINE
                # =================================================

                baseline_url = (
                    cls.build_test_url(
                        endpoint,
                        parameter,
                        "VULNHAWK_REDIRECT_BASELINE"
                    )
                )

                if not cls.is_same_origin(
                    target,
                    baseline_url
                ):
                    continue

                baseline = cls._request(
                    session,
                    baseline_url,
                    allow_redirects=False
                )

                if not baseline.get(
                    "success"
                ):

                    result["errors"].append({
                        "endpoint": endpoint_path,
                        "parameter": parameter,
                        "error": baseline.get(
                            "error",
                            "Baseline request failed."
                        ),
                    })

                    continue

                result[
                    "baseline"
                ].append({
                    "endpoint": endpoint_path,
                    "parameter": parameter,
                    "status_code": baseline.get(
                        "status_code"
                    ),
                    "location": baseline.get(
                        "location"
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
                            payload
                        )
                    )

                    if not cls.is_same_origin(
                        target,
                        test_url
                    ):
                        continue

                    test = cls._request(
                        session,
                        test_url,
                        allow_redirects=False
                    )

                    if not test.get(
                        "success"
                    ):
                        continue

                    location = test.get(
                        "location"
                    )

                    # =================================================
                    # STRONG OPEN REDIRECT EVIDENCE
                    # =================================================

                    if not location:
                        continue

                    external = (
                        cls.is_external_destination(
                            target,
                            location
                        )
                    )

                    if not external:
                        continue

                    final_url = test.get(
                        "final_url"
                    )

                    finding = cls.build_finding(
                        endpoint,
                        parameter,
                        payload,
                        location,
                        final_url
                    )

                    result[
                        "evidence"
                    ].append({
                        "endpoint": endpoint_path,
                        "parameter": parameter,
                        "payload": payload,
                        "location": location,
                        "external": True,
                    })

                    result[
                        "findings"
                    ].append(
                        finding
                    )

                    # Strong evidence found.
                    break

        # =====================================================
        # FINAL DEDUPLICATION
        # =====================================================

        result["findings"] = (
            cls.deduplicate_findings(
                result["findings"]
            )
        )

        return result


# =============================================================
# BACKWARD COMPATIBILITY
# =============================================================

OpenRedirect = OpenRedirectScanner