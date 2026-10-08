"""
=========================================================
 VulnHawk Cookie Security Analyzer
=========================================================
"""

import requests

from config import REQUEST_TIMEOUT


class CookieScanner:

    @staticmethod
    def scan(url):

        results = {}

        try:
            response = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                headers={
                    "User-Agent": "VulnHawk/1.0"
                }
            )

            cookies = response.cookies

            if not cookies:
                return {
                    "Status": "No cookies found"
                }

            for cookie in cookies:

                cookie_name = cookie.name

                results[cookie_name] = {
                    "Secure": cookie.secure,
                    "HttpOnly": "HttpOnly" in cookie._rest,
                    "SameSite": cookie._rest.get("SameSite", "Missing")
                }

            return results

        except Exception as e:

            return {
                "Error": str(e)
            }