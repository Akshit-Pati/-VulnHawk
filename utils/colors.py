"""
=========================================================
 VulnHawk Color Utility
=========================================================
"""

from colorama import Fore, Style, init

# Enable color support
init(autoreset=True)


class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE

    RESET = Style.RESET_ALL
    BRIGHT = Style.BRIGHT

    SUCCESS = GREEN + BRIGHT
    ERROR = RED + BRIGHT
    WARNING = YELLOW + BRIGHT
    INFO = CYAN + BRIGHT


def print_success(message):
    print(f"{Colors.SUCCESS}[+] {message}{Colors.RESET}")


def print_error(message):
    print(f"{Colors.ERROR}[-] {message}{Colors.RESET}")


def print_warning(message):
    print(f"{Colors.WARNING}[!] {message}{Colors.RESET}")


def print_info(message):
    print(f"{Colors.INFO}[*] {message}{Colors.RESET}")


def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BRIGHT}

██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔══██╗██║    ██║██║ ██╔╝
██║   ██║██║   ██║██║     ██╔██╗ ██║███████║███████║██║ █╗ ██║█████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══██║██║███╗██║██╔═██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝

        Automated Web Application Vulnerability Scanner
                    Version 1.0
{Colors.RESET}
"""
    print(banner)