"""
=========================================================
 VulnHawk Nmap Port Scanner
=========================================================
"""

import socket
import nmap
from urllib.parse import urlparse


class PortScanner:

    @staticmethod
    def scan(url):

        try:
            # ---------------------------------------------
            # Extract hostname
            # ---------------------------------------------
            hostname = urlparse(url).hostname

            if not hostname:
                return {
                    "Status": "Invalid target hostname"
                }

            # ---------------------------------------------
            # Resolve hostname to IPv4
            # ---------------------------------------------
            ip_address = socket.gethostbyname(hostname)

            # ---------------------------------------------
            # Initialize Nmap
            # ---------------------------------------------
            scanner = nmap.PortScanner()

            # ---------------------------------------------
            # Run Nmap service/version scan
            # ---------------------------------------------
            scanner.scan(
                ip_address,
                arguments="-4 -T4 -sV --top-ports 100",
                timeout=30
            )

            # ---------------------------------------------
            # Check scan result
            # ---------------------------------------------
            if ip_address not in scanner.all_hosts():

                return {
                    "Status": "Nmap did not return host information",
                    "Hostname": hostname,
                    "IP": ip_address
                }

            results = {}

            # ---------------------------------------------
            # Extract ports and service information
            # ---------------------------------------------
            for protocol in scanner[ip_address].all_protocols():

                ports = scanner[ip_address][protocol].keys()

                for port in sorted(ports):

                    port_data = scanner[ip_address][protocol][port]

                    # -------------------------------------
                    # Port state
                    # -------------------------------------
                    state = port_data.get(
                        "state",
                        "unknown"
                    )

                    # -------------------------------------
                    # Service name
                    # -------------------------------------
                    service = port_data.get(
                        "name",
                        "unknown"
                    )

                    # -------------------------------------
                    # Product detected by Nmap
                    # -------------------------------------
                    product = port_data.get(
                        "product",
                        ""
                    )

                    # -------------------------------------
                    # Version detected by Nmap
                    # -------------------------------------
                    version = port_data.get(
                        "version",
                        ""
                    )

                    # -------------------------------------
                    # Additional Nmap information
                    # -------------------------------------
                    extra_info = port_data.get(
                        "extrainfo",
                        ""
                    )

                    # -------------------------------------
                    # Store structured result
                    # -------------------------------------
                    results[f"{port}/{protocol}"] = {
                        "State": state,
                        "Service": service,
                        "Product": product,
                        "Version": version,
                        "ExtraInfo": extra_info
                    }

            # ---------------------------------------------
            # Final result
            # ---------------------------------------------
            return {
                "Hostname": hostname,
                "IP": ip_address,
                "Ports": results
            }

        # ---------------------------------------------
        # DNS error
        # ---------------------------------------------
        except socket.gaierror as e:

            return {
                "Status": "DNS resolution failed",
                "Error": str(e)
            }

        # ---------------------------------------------
        # General Nmap error
        # ---------------------------------------------
        except Exception as e:

            error_message = str(e)

            if (
    "timed out" in error_message.lower()
    or "timeout from nmap process" in error_message.lower()
):
                return {
                    "Status": "Nmap scan timed out",
                    "Error": "Nmap exceeded the maximum scan duration of 30 seconds."
        }

            return {
                "Status": "Nmap scan failed",
                "Error": error_message
    }
