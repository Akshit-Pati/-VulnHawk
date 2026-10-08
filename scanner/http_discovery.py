import requests
import urllib3
from urllib.parse import urlparse
from config import REQUEST_TIMEOUT

# Suppress warnings because VulnHawk intentionally supports
# controlled certificate inspection during discovery.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPDiscovery:

    USER_AGENT = "VulnHawk/1.0 Security Scanner"

    @staticmethod
    def normalize_url(target: str) -> str:
        target = target.strip()

        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        parsed = urlparse(target)

        if not parsed.netloc:
            raise ValueError("Invalid target URL")

        return target.rstrip("/")

    @classmethod
    def check(cls, target: str) -> dict:

        target = cls.normalize_url(target)
        parsed = urlparse(target)

        original_scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port

        result = {
            "target": target,
            "http": {
                "reachable": False,
                "status_code": None,
                "response_time": None,
                "final_url": None
            },
            "https": {
                "reachable": False,
                "status_code": None,
                "response_time": None,
                "final_url": None
            },
            "redirects_to_https": False,
            "final_url": None,
            "errors": []
        }

        headers = {
            "User-Agent": cls.USER_AGENT
        }

        # ---------------------------------------------------------
        # HTTP CHECK
        # ---------------------------------------------------------
        try:

            if original_scheme == "http":
                http_url = target

            else:
                http_url = "http://" + hostname

                if port:
                    http_url += f":{port}"

            response = requests.get(
                http_url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False
            )

            result["http"] = {
                "reachable": True,
                "status_code": response.status_code,
                "response_time": round(
                    response.elapsed.total_seconds(), 3
                ),
                "final_url": response.url
            }

            if response.url.lower().startswith("https://"):
                result["redirects_to_https"] = True

        except requests.RequestException as error:

            result["errors"].append(
                f"HTTP: {str(error)}"
            )

        # ---------------------------------------------------------
        # HTTPS CHECK
        # ---------------------------------------------------------
        #
        # Important:
        # For a custom HTTP port such as 3000, do NOT blindly
        # convert http://host:3000 into https://host:3000.
        #
        # HTTPS normally uses 443 unless the target explicitly
        # specifies an HTTPS port.
        # ---------------------------------------------------------

        try:

            if original_scheme == "https":

                https_url = target

            else:

                if port and port not in (80, 443):

                    # Custom port supplied as HTTP.
                    # First determine whether HTTPS is available
                    # on the standard HTTPS port instead of testing
                    # TLS against an HTTP service on port 3000.
                    https_url = f"https://{hostname}"

                else:

                    https_url = f"https://{hostname}"

                    if port == 443:
                        https_url += ":443"

            response = requests.get(
                https_url,
                headers=headers,
                timeout=10,
                allow_redirects=True,
                verify=False
            )

            result["https"] = {
                "reachable": True,
                "status_code": response.status_code,
                "response_time": round(
                    response.elapsed.total_seconds(), 3
                ),
                "final_url": response.url
            }

            result["final_url"] = response.url

        except requests.RequestException as error:

            error_text = str(error)

            # HTTPS being unavailable is expected for HTTP-only
            # targets and should not be treated as an error.
            if original_scheme == "http":
                pass
            else:
                result["errors"].append(
                    f"HTTPS: {error_text}"
                )

        # ---------------------------------------------------------
        # FINAL URL SELECTION
        # ---------------------------------------------------------

        if result["https"]["reachable"]:
            result["final_url"] = result["https"]["final_url"]

        elif result["http"]["reachable"]:
            result["final_url"] = result["http"]["final_url"]

        return result