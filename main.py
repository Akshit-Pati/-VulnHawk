from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(InsecureRequestWarning)

from utils.colors import *
from utils.logger import Logger
from utils.validator import URLValidator

from scanner.header_scanner import HeaderScanner
from scanner.ssl_checker import SSLChecker
from scanner.technologies import TechnologyDetector
from scanner.robots_checker import RobotsChecker
from scanner.sitemap_checker import SitemapChecker
from scanner.cookies import CookieScanner
from scanner.port_scanner import PortScanner


# =========================================================
# VulnHawk Banner
# =========================================================

print_banner()


# =========================================================
# Target Input
# =========================================================

target = input("Enter Target URL : ").strip()

target = URLValidator.normalize(target)


# =========================================================
# URL Validation
# =========================================================

if not URLValidator.is_valid(target):

    print_error("Invalid URL")
    Logger.error("Invalid URL")

    exit()


print_success("URL Format Valid")


# =========================================================
# Target Reachability
# =========================================================

status = URLValidator.is_reachable(target)


if status:

    print_success(f"Target Reachable (HTTP {status})")
    Logger.success(f"{target} HTTP {status}")


    # =====================================================
    # Security Header Scanner
    # =====================================================

    print_info("\nScanning Security Headers...\n")

    results = HeaderScanner.scan(target)

    for header, header_status in results.items():

        if header_status == "Present":

            print_success(
                f"{header}: {header_status}"
            )

        elif header_status == "Missing":

            print_warning(
                f"{header}: {header_status}"
            )

        else:

            print_error(
                f"{header}: {header_status}"
            )


    # =====================================================
    # SSL Certificate Scanner
    # =====================================================

    print_info("\nScanning SSL Certificate...\n")

    ssl_result = SSLChecker.scan(target)

    for key, value in ssl_result.items():

        print_info(
            f"{key}: {value}"
        )


    # =====================================================
    # Technology Detection
    # =====================================================

    print_info("\nTechnology Detection...\n")

    tech = TechnologyDetector.scan(target)

    for key, value in tech.items():

        print_info(
            f"{key}: {value}"
        )


    # =====================================================
    # robots.txt Scanner
    # =====================================================

    print_info("\nScanning robots.txt...\n")

    robots = RobotsChecker.scan(target)

    for key, value in robots.items():

        print_info(
            f"{key}: {value}"
        )


    # =====================================================
    # Sitemap Scanner
    # =====================================================

    print_info("\nScanning sitemap.xml...\n")

    sitemap = SitemapChecker.scan(target)

    for key, value in sitemap.items():

        print_info(
            f"{key}: {value}"
        )


    # =====================================================
    # Cookie Security Scanner
    # =====================================================

    print_info("\nScanning Cookie Security...\n")

    cookies = CookieScanner.scan(target)


    # No Cookies
    if (
        "Status" in cookies
        and cookies["Status"] == "No cookies found"
    ):

        print_info(
            "Status: No cookies found"
        )


    # Scanner Error
    elif "Error" in cookies:

        print_error(
            f"Error: {cookies['Error']}"
        )


    # Cookies Found
    else:

        for cookie, details in cookies.items():

            print_info(
                f"Cookie: {cookie}"
            )

            if isinstance(details, dict):

                for key, value in details.items():

                    print_info(
                        f"  {key}: {value}"
                    )

            else:

                print_info(
                    f"  {details}"
                )

# ==========================
# Nmap Port Scanner
# ==========================
print_info("\nScanning Network Ports...\n")

ports = PortScanner.scan(target)

if "Error" in ports:
    print_error(f"Error: {ports['Error']}")

elif "Status" in ports:
    print_info(f"Status: {ports['Status']}")

else:

    for port, details in ports.items():

        print_info(f"Port: {port}")

        for key, value in details.items():
            print_info(f"  {key}: {value}")
# =========================================================
# Target Not Reachable
# =========================================================

    else:

        print_error(
        "Target is Not Reachable"
    )

    Logger.error(
        target + " Not Reachable"
    )