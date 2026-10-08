"""
=========================================================
 VulnHawk Security Header Scanner
=========================================================
"""

import requests
from config import REQUIRED_HEADERS, REQUEST_TIMEOUT


class HeaderScanner:

    @staticmethod
    def scan(url):

        result = {}

        try:

            response = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                headers={
                    "User-Agent": "VulnHawk/1.0"
                }
            )

            headers = response.headers

            for header in REQUIRED_HEADERS:

                if header in headers:
                    result[header] = "Present"
                else:
                    result[header] = "Missing"

            return result

        except Exception as e:

            return {
                "Error": str(e)
            }