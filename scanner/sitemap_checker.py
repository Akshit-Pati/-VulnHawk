import requests
from config import REQUEST_TIMEOUT


class SitemapChecker:

    @staticmethod
    def scan(url):
        sitemap_url = url.rstrip("/") + "/sitemap.xml"

        try:
            response = requests.get(
                sitemap_url,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                headers={"User-Agent": "VulnHawk/1.0"}
            )

            if response.status_code == 200:
                return {
                    "Status": "Found",
                    "URL": sitemap_url,
                    "Content": response.text[:500]
                }

            return {
                "Status": "Not Found",
                "URL": sitemap_url
            }

        except Exception as e:
            return {
                "Status": "Error",
                "Error": str(e)
            }