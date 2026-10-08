import requests
from config import REQUEST_TIMEOUT


class RobotsChecker:

    @staticmethod
    def scan(url):
        robots_url = url.rstrip("/") + "/robots.txt"

        try:
            response = requests.get(
                robots_url,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                headers={"User-Agent": "VulnHawk/1.0"}
            )

            if response.status_code == 200:
                return {
                    "Status": "Found",
                    "URL": robots_url,
                    "Content": response.text[:500]   # First 500 characters
                }

            return {
                "Status": "Not Found",
                "URL": robots_url
            }

        except Exception as e:
            return {
                "Status": "Error",
                "Error": str(e)
            }