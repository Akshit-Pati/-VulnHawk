import requests

from urllib.parse import (
    urljoin,
    urlparse,
    parse_qsl,
    urlencode
)

from scanner.scope_validator import ScopeValidator


class XSSScanner:

    USER_AGENT = "VulnHawk/1.0 Security Scanner"

    MARKER = "VULNHAWK_XSS_TEST_7F3A"

    # -------------------------------------------------
    # CONTEXT DETECTION
    # -------------------------------------------------

    @staticmethod
    def detect_context(response_text, marker):

        if not response_text:
            return "UNKNOWN"

        # Marker inside a script block
        script_pattern = (
            r"<script[^>]*>.*?"
            + marker
            + r".*?</script>"
        )

        if __import__("re").search(
            script_pattern,
            response_text,
            __import__("re").IGNORECASE
            | __import__("re").DOTALL
        ):
            return "JAVASCRIPT"

        # Marker inside an HTML attribute
        attribute_pattern = (
            r"<[^>]+[^>\"']"
            + marker
            + r"[^>]*>"
        )

        if __import__("re").search(
            attribute_pattern,
            response_text,
            __import__("re").IGNORECASE
        ):
            return "HTML_ATTRIBUTE"

        # Marker reflected as normal HTML text
        if marker in response_text:
            return "HTML_TEXT"

        return "UNKNOWN"

    # -------------------------------------------------
    # BUILD TEST URL
    # -------------------------------------------------

    @staticmethod
    def build_test_url(
        endpoint_url,
        parameter,
        value
    ):

        parsed = urlparse(endpoint_url)

        query_parameters = dict(
            parse_qsl(
                parsed.query,
                keep_blank_values=True
            )
        )

        query_parameters[parameter] = value

        new_query = urlencode(
            query_parameters,
            doseq=True
        )

        return parsed._replace(
            query=new_query,
            fragment=""
        ).geturl()

    # -------------------------------------------------
    # REFLECTION ANALYSIS
    # -------------------------------------------------

    @classmethod
    def analyze_reflection(
        cls,
        response_text
    ):

        if not response_text:
            return None

        if cls.MARKER not in response_text:
            return None

        context = cls.detect_context(
            response_text,
            cls.MARKER
        )

        return {
            "marker": cls.MARKER,
            "context": context
        }

    # -------------------------------------------------
    # MAIN SCANNER
    # -------------------------------------------------

    @classmethod
    def scan(
        cls,
        target,
        parameter_map=None,
        timeout=10
    ):

        parameter_map = parameter_map or {}

        tested_parameters = []
        reflections = []
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
                        "error": "Endpoint outside target scope"
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

                # -------------------------------------------------
                # Build marker URL
                # -------------------------------------------------

                test_url = cls.build_test_url(
                    endpoint_url,
                    parameter,
                    cls.MARKER
                )

                # -------------------------------------------------
                # Send request
                # -------------------------------------------------

                try:

                    response = session.get(
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
                            "error": str(error)
                        }
                    )

                    continue

                except Exception as error:

                    errors.append(
                        {
                            "endpoint": endpoint_path,
                            "parameter": parameter,
                            "error": str(error)
                        }
                    )

                    continue

                # -------------------------------------------------
                # Redirect scope validation
                # -------------------------------------------------

                if not ScopeValidator.is_same_origin(
                    target,
                    response.url
                ):

                    errors.append(
                        {
                            "endpoint": endpoint_path,
                            "parameter": parameter,
                            "error": (
                                "Redirected outside target scope"
                            )
                        }
                    )

                    continue

                # -------------------------------------------------
                # Analyze reflection
                # -------------------------------------------------

                reflection = cls.analyze_reflection(
                    response.text
                )

                if not reflection:
                    continue

                # -------------------------------------------------
                # Reflection result
                # -------------------------------------------------

                reflection_result = {
                    "endpoint": endpoint_path,
                    "parameter": parameter,
                    "context": reflection["context"],
                    "status_code": response.status_code
                }

                reflections.append(
                    reflection_result
                )

                # -------------------------------------------------
                # Evidence-based finding
                # -------------------------------------------------

                findings.append(
                    {
                        "title": "Potential Reflected XSS Sink",
                        "severity": "Low",
                        "confidence": "Medium",
                        "endpoint": endpoint_path,
                        "parameter": parameter,
                        "evidence": {
                            "marker_reflected": True,
                            "context": reflection["context"],
                            "status_code": response.status_code
                        },
                        "description": (
                            "The supplied test marker was reflected "
                            "in the HTTP response. Reflection alone "
                            "does not confirm executable XSS."
                        ),
                        "recommendation": (
                            "Review output encoding and "
                            "context-specific HTML/JavaScript "
                            "escaping for this parameter."
                        )
                    }
                )

        # =================================================
        # FINAL RESULT
        # =================================================

        return {
            "target": target,
            "tested_parameters": tested_parameters,
            "reflections": reflections,
            "findings": findings,
            "errors": errors
        }