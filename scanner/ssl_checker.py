"""
=========================================================
 VulnHawk SSL / TLS Certificate Scanner
=========================================================
"""

import ssl
import socket
from urllib.parse import urlparse


class SSLChecker:

    @staticmethod
    def scan(url):

        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname

            # -------------------------------------------------
            # HTTP targets do not require TLS certificate checks
            # -------------------------------------------------

            if scheme != "https":
                return {
                    "Status": "Not Applicable",
                    "Reason": "Target is using HTTP rather than HTTPS."
                }

            if not hostname:
                return {
                    "Status": "Certificate Error",
                    "Error": "Unable to determine target hostname."
                }

            port = parsed.port or 443

            context = ssl.create_default_context()

            with socket.create_connection(
                (hostname, port),
                timeout=10
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=hostname
                ) as ssock:

                    cert = ssock.getpeercert()

            return {
                "Status": "Secure",
                "Issuer": dict(
                    x[0] for x in cert.get("issuer", [])
                ),
                "Subject": dict(
                    x[0] for x in cert.get("subject", [])
                ),
                "Valid From": cert.get("notBefore"),
                "Valid Until": cert.get("notAfter")
            }

        except ssl.CertificateError as error:

            return {
                "Status": "Certificate Error",
                "Error": str(error)
            }

        except ssl.SSLError as error:

            return {
                "Status": "Certificate Error",
                "Error": str(error)
            }

        except (socket.timeout, ConnectionRefusedError, OSError) as error:

            return {
                "Status": "Unavailable",
                "Error": str(error)
            }

        except Exception as error:

            return {
                "Status": "Unavailable",
                "Error": str(error)
            }