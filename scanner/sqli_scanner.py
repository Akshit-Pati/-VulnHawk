import re
import requests

from urllib.parse import (
    urljoin,
    urlparse,
    parse_qsl,
    urlencode
)

from scanner.scope_validator import ScopeValidator


class SQLiScanner:

    USER_AGENT = "VulnHawk/1.0 Security Scanner"

    BASELINE_VALUE = "VULNHAWK_BASELINE_7F3A"

    TEST_VALUES = [
        "'",
        '"',
        "' OR '1'='1"
    ]

    SQL_ERROR_SIGNATURES = [
        "sql syntax",
        "mysql",
        "mysqli",
        "postgresql",
        "postgres",
        "sqlite",
        "sqlite3",
        "oracle",
        "ora-",
        "odbc",
        "jdbc",
        "sqlstate",
        "syntax error",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "invalid sql",
        "database error"
    ]

    # =================================================
    # SQL ERROR DETECTION
    # =================================================

    @classmethod
    def detect_sql_errors(cls, response_text):

        if not response_text:
            return []

        text = response_text.lower()

        detected = []

        for signature in cls.SQL_ERROR_SIGNATURES:

            if signature.lower() in text:
                detected.append(
                    signature
                )

        return sorted(
            set(detected)
        )

    # =================================================
    # BUILD TEST URL
    # =================================================

    @staticmethod
    def build_test_url(
        endpoint_url,
        parameter,
        value
    ):

        parsed = urlparse(
            endpoint_url
        )

        query_parameters = dict(
            parse_qsl(
                parsed.query,
                keep_blank_values=True
            )
        )

        query_parameters[
            parameter
        ] = value

        new_query = urlencode(
            query_parameters,
            doseq=True
        )

        return parsed._replace(
            query=new_query,
            fragment=""
        ).geturl()

    # =================================================
    # RESPONSE SIMILARITY
    # =================================================

    @staticmethod
    def response_similarity(
        baseline_text,
        test_text
    ):

        baseline_length = len(
            baseline_text or ""
        )

        test_length = len(
            test_text or ""
        )

        if baseline_length == 0 and test_length == 0:
            return 1.0

        if baseline_length == 0 or test_length == 0:
            return 0.0

        difference = abs(
            baseline_length - test_length
        )

        maximum = max(
            baseline_length,
            test_length
        )

        similarity = (
            1 - (difference / maximum)
        )

        return round(
            max(
                0.0,
                min(
                    1.0,
                    similarity
                )
            ),
            3
        )

    # =================================================
    # RESPONSE ANALYSIS
    # =================================================

    @classmethod
    def analyze_response(
        cls,
        baseline_response,
        test_response,
        test_value
    ):

        baseline_text = (
            baseline_response.text
            if baseline_response
            else ""
        )

        test_text = (
            test_response.text
            if test_response
            else ""
        )

        baseline_errors = (
            cls.detect_sql_errors(
                baseline_text
            )
        )

        test_errors = (
            cls.detect_sql_errors(
                test_text
            )
        )

        # Only errors appearing after the test
        # are useful evidence.
        new_sql_errors = sorted(
            set(test_errors)
            - set(baseline_errors)
        )

        baseline_status = (
            baseline_response.status_code
            if baseline_response
            else None
        )

        test_status = (
            test_response.status_code
            if test_response
            else None
        )

        similarity = (
            cls.response_similarity(
                baseline_text,
                test_text
            )
        )

        status_changed = (
            baseline_status != test_status
        )

        significant_difference = (
            similarity < 0.70
        )

        return {
            "test_value": test_value,
            "baseline_status_code": baseline_status,
            "test_status_code": test_status,
            "baseline_response_length": len(
                baseline_text
            ),
            "test_response_length": len(
                test_text
            ),
            "similarity": similarity,
            "status_changed": status_changed,
            "significant_difference": (
                significant_difference
            ),
            "baseline_sql_errors": (
                baseline_errors
            ),
            "test_sql_errors": (
                test_errors
            ),
            "new_sql_errors": (
                new_sql_errors
            )
        }

    # =================================================
    # MAIN SCANNER
    # =================================================

    @classmethod
    def scan(
        cls,
        target,
        parameter_map=None,
        timeout=10
    ):

        parameter_map = parameter_map or {}

        tested_parameters = []

        baseline_results = []

        evidence = []

        findings = []

        errors = []

        session = requests.Session()

        session.headers.update(
            {
                "User-Agent": cls.USER_AGENT
            }
        )

        # =================================================
        # ENDPOINT LOOP
        # =================================================

        for endpoint_path, parameters in parameter_map.items():

            if not parameters:
                continue

            endpoint_url = urljoin(
                target.rstrip("/") + "/",
                endpoint_path.lstrip("/")
            )

            # -------------------------------------------------
            # Scope validation
            # -------------------------------------------------

            if not ScopeValidator.is_same_origin(
                target,
                endpoint_url
            ):

                errors.append(
                    {
                        "endpoint": endpoint_path,
                        "error": (
                            "Endpoint outside "
                            "target scope"
                        )
                    }
                )

                continue

            # =================================================
            # PARAMETER LOOP
            # =================================================

            for parameter in parameters:

                tested_parameters.append(
                    {
                        "endpoint": endpoint_path,
                        "parameter": parameter
                    }
                )

                # =================================================
                # BASELINE
                # =================================================

                baseline_url = cls.build_test_url(
                    endpoint_url,
                    parameter,
                    cls.BASELINE_VALUE
                )

                try:

                    baseline_response = session.get(
                        baseline_url,
                        timeout=timeout,
                        allow_redirects=True,
                        verify=False
                    )

                except requests.RequestException as error:

                    errors.append(
                        {
                            "endpoint": endpoint_path,
                            "parameter": parameter,
                            "stage": "baseline",
                            "error": str(error)
                        }
                    )

                    continue

                except Exception as error:

                    errors.append(
                        {
                            "endpoint": endpoint_path,
                            "parameter": parameter,
                            "stage": "baseline",
                            "error": str(error)
                        }
                    )

                    continue

                # -------------------------------------------------
                # Baseline redirect scope
                # -------------------------------------------------

                if not ScopeValidator.is_same_origin(
                    target,
                    baseline_response.url
                ):

                    errors.append(
                        {
                            "endpoint": endpoint_path,
                            "parameter": parameter,
                            "stage": "baseline",
                            "error": (
                                "Baseline request redirected "
                                "outside target scope"
                            )
                        }
                    )

                    continue

                baseline_sql_errors = (
                    cls.detect_sql_errors(
                        baseline_response.text
                    )
                )

                baseline_result = {
                    "endpoint": endpoint_path,
                    "parameter": parameter,
                    "status_code": (
                        baseline_response.status_code
                    ),
                    "response_length": len(
                        baseline_response.text
                    ),
                    "sql_errors": (
                        baseline_sql_errors
                    )
                }

                baseline_results.append(
                    baseline_result
                )

                # =================================================
                # TEST PAYLOADS
                # =================================================

                for test_value in cls.TEST_VALUES:

                    test_url = cls.build_test_url(
                        endpoint_url,
                        parameter,
                        test_value
                    )

                    try:

                        test_response = session.get(
                            test_url,
                            timeout=timeout,
                            allow_redirects=True,
                            verify=False
                        )

                    except requests.RequestException as error:

                        errors.append(
                            {
                                "endpoint": endpoint_path,
                                "parameter": parameter,
                                "stage": "test",
                                "test_value": test_value,
                                "error": str(error)
                            }
                        )

                        continue

                    except Exception as error:

                        errors.append(
                            {
                                "endpoint": endpoint_path,
                                "parameter": parameter,
                                "stage": "test",
                                "test_value": test_value,
                                "error": str(error)
                            }
                        )

                        continue

                    # -------------------------------------------------
                    # Test redirect scope
                    # -------------------------------------------------

                    if not ScopeValidator.is_same_origin(
                        target,
                        test_response.url
                    ):

                        errors.append(
                            {
                                "endpoint": endpoint_path,
                                "parameter": parameter,
                                "stage": "test",
                                "test_value": test_value,
                                "error": (
                                    "Test request redirected "
                                    "outside target scope"
                                )
                            }
                        )

                        continue

                    analysis = cls.analyze_response(
                        baseline_response,
                        test_response,
                        test_value
                    )

                    # -------------------------------------------------
                    # Evidence decision
                    # -------------------------------------------------

                    has_new_sql_error = bool(
                        analysis[
                            "new_sql_errors"
                        ]
                    )

                    status_changed = (
                        analysis[
                            "status_changed"
                        ]
                    )

                    significant_difference = (
                        analysis[
                            "significant_difference"
                        ]
                    )

                    # ---------------------------------------------
                    # Strong evidence
                    # ---------------------------------------------

                    if (
                        has_new_sql_error
                        and
                        (
                            status_changed
                            or
                            significant_difference
                        )
                    ):

                        evidence_item = {
                            "endpoint": endpoint_path,
                            "parameter": parameter,
                            "test_value": test_value,
                            "evidence_type": (
                                "SQL error + response differential"
                            ),
                            "confidence": "High",
                            "severity": "High",
                            "details": analysis
                        }

                        evidence.append(
                            evidence_item
                        )

                        findings.append(
                            {
                                "title": (
                                    "Potential SQL Injection"
                                ),
                                "severity": "High",
                                "confidence": "High",
                                "endpoint": endpoint_path,
                                "parameter": parameter,
                                "evidence": analysis,
                                "description": (
                                    "The test input produced "
                                    "new database error signatures "
                                    "together with a response "
                                    "difference compared with "
                                    "the baseline."
                                ),
                                "recommendation": (
                                    "Review server-side parameter "
                                    "handling and use parameterized "
                                    "queries or prepared statements."
                                )
                            }
                        )

                    # ---------------------------------------------
                    # SQL error only
                    # ---------------------------------------------

                    elif has_new_sql_error:

                        evidence_item = {
                            "endpoint": endpoint_path,
                            "parameter": parameter,
                            "test_value": test_value,
                            "evidence_type": (
                                "New SQL error signature"
                            ),
                            "confidence": "Medium",
                            "severity": "Medium",
                            "details": analysis
                        }

                        evidence.append(
                            evidence_item
                        )

                        findings.append(
                            {
                                "title": (
                                    "Potential SQL Injection Indicator"
                                ),
                                "severity": "Medium",
                                "confidence": "Medium",
                                "endpoint": endpoint_path,
                                "parameter": parameter,
                                "evidence": analysis,
                                "description": (
                                    "The test input produced "
                                    "a database-related error "
                                    "signature that was not "
                                    "present in the baseline."
                                ),
                                "recommendation": (
                                    "Inspect server-side query "
                                    "construction and use "
                                    "parameterized queries."
                                )
                            }
                        )

                    # ---------------------------------------------
                    # Differential response only
                    # ---------------------------------------------

                    elif (
                        status_changed
                        and
                        significant_difference
                    ):

                        evidence_item = {
                            "endpoint": endpoint_path,
                            "parameter": parameter,
                            "test_value": test_value,
                            "evidence_type": (
                                "Response differential"
                            ),
                            "confidence": "Low",
                            "severity": "Info",
                            "details": analysis
                        }

                        evidence.append(
                            evidence_item
                        )

                        findings.append(
                            {
                                "title": (
                                    "Input-Dependent "
                                    "Response Anomaly"
                                ),
                                "severity": "Info",
                                "confidence": "Low",
                                "endpoint": endpoint_path,
                                "parameter": parameter,
                                "evidence": analysis,
                                "description": (
                                    "The response changed "
                                    "significantly after the "
                                    "test input. This alone "
                                    "does not establish SQL injection."
                                ),
                                "recommendation": (
                                    "Review the endpoint manually "
                                    "before treating this behavior "
                                    "as a vulnerability."
                                )
                            }
                        )

        # =================================================
        # REMOVE DUPLICATE FINDINGS
        # =================================================

        unique_findings = []

        finding_keys = set()

        for finding in findings:

            key = (
                finding.get("title"),
                finding.get("endpoint"),
                finding.get("parameter")
            )

            if key in finding_keys:
                continue

            finding_keys.add(
                key
            )

            unique_findings.append(
                finding
            )

        # =================================================
        # FINAL RESULT
        # =================================================

        return {
            "target": target,
            "tested_parameters": tested_parameters,
            "baseline": baseline_results,
            "evidence": evidence,
            "findings": unique_findings,
            "errors": errors
        }