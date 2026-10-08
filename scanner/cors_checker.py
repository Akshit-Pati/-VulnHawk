import requests
from config import REQUEST_TIMEOUT


class CORSChecker:
    """
    Passive and controlled CORS configuration analyzer.
    """

    USER_AGENT = "VulnHawk/1.0 Security Scanner"

    @staticmethod
    def check(target):
        """
        Analyze CORS configuration of the target.
        """

        result = {
            "target": target,
            "cors_enabled": False,
            "allow_origin": None,
            "allow_credentials": None,
            "allow_methods": None,
            "allow_headers": None,
            "findings": [],
            "errors": []
        }

        try:
            response = requests.get(
                target,
                headers={
                    "User-Agent": CORSChecker.USER_AGENT
                },
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )

            headers = {
                key.lower(): value.strip()
                for key, value in response.headers.items()
            }

            allow_origin = headers.get(
                "access-control-allow-origin"
            )

            allow_credentials = headers.get(
                "access-control-allow-credentials"
            )

            allow_methods = headers.get(
                "access-control-allow-methods"
            )

            allow_headers = headers.get(
                "access-control-allow-headers"
            )

            result["allow_origin"] = allow_origin
            result["allow_credentials"] = allow_credentials
            result["allow_methods"] = allow_methods
            result["allow_headers"] = allow_headers

            if allow_origin:
                result["cors_enabled"] = True

            # ---------------------------------
            # Wildcard origin
            # ---------------------------------

            if allow_origin == "*":

                result["findings"].append({
                    "type": "CORS Wildcard Origin",
                    "severity": "Low",
                    "description": (
                        "The application allows cross-origin "
                        "requests from any origin."
                    ),
                    "evidence": (
                        "Access-Control-Allow-Origin: *"
                    ),
                    "recommendation": (
                        "Restrict allowed origins to trusted "
                        "application domains."
                    )
                })

            # ---------------------------------
            # Credentials with wildcard origin
            # ---------------------------------

            if (
                allow_origin == "*"
                and allow_credentials
                and allow_credentials.lower() == "true"
            ):

                result["findings"].append({
                    "type": "CORS Wildcard with Credentials",
                    "severity": "High",
                    "description": (
                        "The server allows wildcard cross-origin "
                        "access while enabling credentials."
                    ),
                    "evidence": (
                        "Access-Control-Allow-Origin: *; "
                        "Access-Control-Allow-Credentials: true"
                    ),
                    "recommendation": (
                        "Use an explicit trusted origin and "
                        "review credentialed cross-origin access."
                    )
                })

        except requests.RequestException as error:

            result["errors"].append(str(error))

        except Exception as error:

            result["errors"].append(str(error))

        return result