import requests
from urllib.parse import urlparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class URLValidator:

    @staticmethod
    def normalize(url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url

    @staticmethod
    def is_valid(url: str):
        result = urlparse(url)
        return bool(result.scheme and result.netloc)

    @staticmethod
    def is_reachable(url: str):
        try:
            response = requests.get(
                url,
                timeout=10,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0"
                }
            )

            return response.status_code

        except Exception as e:
            print(f"DEBUG: {e}")
            return None