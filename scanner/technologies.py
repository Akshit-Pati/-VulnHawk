"""
=========================================================
 VulnHawk Technology Detection Module
=========================================================
 Evidence-Based Technology Fingerprinting V4
=========================================================
"""

import re
import requests
import urllib3
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


class TechnologyDetector:

    TIMEOUT = 8

    # Maximum same-origin JavaScript bundles to inspect
    MAX_JS_FILES = 10

    # Maximum JavaScript bytes inspected per file
    MAX_JS_SIZE = 2 * 1024 * 1024

    HEADERS = {
        "User-Agent": "VulnHawk/1.0"
    }

    # =====================================================
    # MAIN SCANNER
    # =====================================================

    @staticmethod
    def scan(url):

        result = {
            "Server": "Unknown",
            "Powered By": "Unknown",
            "Framework": "Unknown",
            "Technologies": [],
            "Evidence": [],
            "Errors": []
        }

        try:

            response = requests.get(
                url,
                timeout=TechnologyDetector.TIMEOUT,
                verify=False,
                headers=TechnologyDetector.HEADERS
            )

            response.raise_for_status()

            html = response.text

            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            # =================================================
            # SERVER HEADER
            # =================================================

            if "server" in headers:

                result["Server"] = headers["server"]

                TechnologyDetector._add_evidence(
                    result,
                    technology=headers["server"],
                    category="Web Server",
                    confidence="High",
                    source="HTTP Header",
                    evidence=(
                        f"Server: {headers['server']}"
                    )
                )

            # =================================================
            # X-POWERED-BY
            # =================================================

            if "x-powered-by" in headers:

                result["Powered By"] = (
                    headers["x-powered-by"]
                )

                TechnologyDetector._add_evidence(
                    result,
                    technology=headers["x-powered-by"],
                    category="Platform",
                    confidence="High",
                    source="HTTP Header",
                    evidence=(
                        f"X-Powered-By: "
                        f"{headers['x-powered-by']}"
                    )
                )

            # =================================================
            # HTML TITLE
            # =================================================

            title_match = re.search(
                r"<title[^>]*>(.*?)</title>",
                html,
                re.IGNORECASE | re.DOTALL
            )

            if title_match:

                title = re.sub(
                    r"\s+",
                    " ",
                    title_match.group(1)
                ).strip()

                if title:

                    # -----------------------------------------
                    # OWASP JUICE SHOP
                    # -----------------------------------------

                    if (
                        "owasp juice shop"
                        in title.lower()
                    ):

                        TechnologyDetector._add_evidence(
                            result,
                            technology="OWASP Juice Shop",
                            category="Web Application",
                            confidence="High",
                            source="HTML Title",
                            evidence=(
                                f"<title>{title}</title>"
                            )
                        )

            # =================================================
            # META GENERATOR
            # =================================================

            generator_match = re.search(
                r'<meta[^>]+name=["\']generator["\']'
                r'[^>]+content=["\']([^"\']+)',
                html,
                re.IGNORECASE
            )

            if generator_match:

                generator = (
                    generator_match.group(1).strip()
                )

                TechnologyDetector._add_evidence(
                    result,
                    technology=generator,
                    category="CMS / Generator",
                    confidence="High",
                    source="HTML Meta Tag",
                    evidence=(
                        f'meta generator: "{generator}"'
                    )
                )

            # =================================================
            # HTML SIGNATURES
            # =================================================

            TechnologyDetector._scan_html_signatures(
                html,
                result
            )

            # =================================================
            # JAVASCRIPT URL DISCOVERY
            # =================================================

            js_urls = TechnologyDetector._extract_js_urls(
                url,
                html
            )

            # =================================================
            # JAVASCRIPT BUNDLE ANALYSIS
            # =================================================

            for js_url in js_urls[
                :TechnologyDetector.MAX_JS_FILES
            ]:

                TechnologyDetector._scan_javascript(
                    js_url,
                    url,
                    result
                )

            # =================================================
            # PRIMARY FRAMEWORK
            # =================================================

            TechnologyDetector._set_framework(
                result
            )

            return result

        except requests.RequestException as exc:

            result["Errors"].append(
                f"Technology detection request failed: {exc}"
            )

            return result

        except Exception as exc:

            result["Errors"].append(
                f"Technology detection failed: {exc}"
            )

            return result

    # =====================================================
    # HTML SIGNATURES
    # =====================================================

    @staticmethod
    def _scan_html_signatures(
        html,
        result
    ):

        html_lower = html.lower()

        # -------------------------------------------------
        # WordPress
        # -------------------------------------------------

        if any(
            marker in html_lower
            for marker in (
                "/wp-content/",
                "/wp-includes/",
                "/wp-json/"
            )
        ):

            TechnologyDetector._add_evidence(
                result,
                technology="WordPress",
                category="CMS",
                confidence="High",
                source="HTML Signature",
                evidence=(
                    "WordPress resource path detected"
                )
            )

        # -------------------------------------------------
        # Django
        # -------------------------------------------------

        if "csrfmiddlewaretoken" in html_lower:

            TechnologyDetector._add_evidence(
                result,
                technology="Django",
                category="Web Framework",
                confidence="High",
                source="HTML Signature",
                evidence=(
                    "csrfmiddlewaretoken detected"
                )
            )

        # -------------------------------------------------
        # Laravel
        # -------------------------------------------------

        if "laravel_session" in html_lower:

            TechnologyDetector._add_evidence(
                result,
                technology="Laravel",
                category="Web Framework",
                confidence="High",
                source="HTML / Cookie Signature",
                evidence=(
                    "laravel_session detected"
                )
            )

        # -------------------------------------------------
        # Bootstrap
        # -------------------------------------------------

        if re.search(
            r"bootstrap(?:\.min)?\.(?:css|js)",
            html_lower
        ):

            TechnologyDetector._add_evidence(
                result,
                technology="Bootstrap",
                category="CSS / UI Framework",
                confidence="Medium",
                source="HTML Resource Signature",
                evidence=(
                    "Bootstrap resource detected"
                )
            )

        # -------------------------------------------------
        # Tailwind CSS
        # -------------------------------------------------

        if "tailwindcss" in html_lower:

            TechnologyDetector._add_evidence(
                result,
                technology="Tailwind CSS",
                category="CSS Framework",
                confidence="Medium",
                source="HTML Signature",
                evidence=(
                    "Tailwind CSS marker detected"
                )
            )

    # =====================================================
    # JAVASCRIPT URL EXTRACTION
    # =====================================================

    @staticmethod
    def _extract_js_urls(
        base_url,
        html
    ):

        matches = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE
        )

        base = urlparse(base_url)

        js_urls = []
        seen = set()

        for src in matches:

            full_url = urljoin(
                base_url,
                src
            )

            parsed = urlparse(full_url)

            # -------------------------------------------------
            # SAME ORIGIN ONLY
            # -------------------------------------------------

            if (
                parsed.scheme != base.scheme
                or parsed.hostname != base.hostname
                or parsed.port != base.port
            ):
                continue

            # -------------------------------------------------
            # JAVASCRIPT RESOURCE ONLY
            # -------------------------------------------------

            if not (
                parsed.path.endswith(".js")
                or parsed.path.endswith(".mjs")
                or parsed.path.endswith(".js/")
            ):
                continue

            if full_url not in seen:

                seen.add(full_url)
                js_urls.append(full_url)

        return js_urls

    # =====================================================
    # JAVASCRIPT BUNDLE ANALYSIS
    # =====================================================

    @staticmethod
    def _scan_javascript(
        js_url,
        base_url,
        result
    ):

        try:

            response = requests.get(
                js_url,
                timeout=TechnologyDetector.TIMEOUT,
                verify=False,
                headers=TechnologyDetector.HEADERS
            )

            if response.status_code != 200:
                return

            # -------------------------------------------------
            # CONTENT SIZE LIMIT
            # -------------------------------------------------

            content = response.content

            if len(content) > TechnologyDetector.MAX_JS_SIZE:

                content = content[
                    :TechnologyDetector.MAX_JS_SIZE
                ]

            js = content.decode(
                "utf-8",
                errors="ignore"
            )

            js_lower = js.lower()

            filename = (
                urlparse(js_url)
                .path
                .split("/")[-1]
            )

            # =================================================
            # ANGULAR MULTI-SIGNAL DETECTION
            # =================================================

            angular_count = js_lower.count(
                "angular"
            )

            nghost_count = js_lower.count(
                "nghost"
            )

            ngcontent_count = js_lower.count(
                "ngcontent"
            )

            component_count = js_lower.count(
                "component"
            )

            injector_count = js_lower.count(
                "injector"
            )

            zone_count = js_lower.count(
                "zone"
            )

            angular_signals = 0

            if angular_count >= 3:
                angular_signals += 1

            if nghost_count >= 2:
                angular_signals += 1

            if ngcontent_count >= 5:
                angular_signals += 1

            if component_count >= 10:
                angular_signals += 1

            if injector_count >= 3:
                angular_signals += 1

            if zone_count >= 5:
                angular_signals += 1

            # -------------------------------------------------
            # Require multiple signals
            # -------------------------------------------------

            if angular_signals >= 3:

                evidence = (
                    f"Angular multi-signal fingerprint "
                    f"detected in {filename}: "
                    f"angular={angular_count}, "
                    f"nghost={nghost_count}, "
                    f"ngcontent={ngcontent_count}, "
                    f"component={component_count}, "
                    f"injector={injector_count}, "
                    f"zone={zone_count}"
                )

                TechnologyDetector._add_evidence(
                    result,
                    technology="Angular",
                    category="JavaScript Framework",
                    confidence="High",
                    source="JavaScript Bundle",
                    evidence=evidence
                )

            # =================================================
            # REACT
            # =================================================

            react_markers = [
                "react.createelement",
                "reactdom",
                "__reactfiber",
                "__reactprops"
            ]

            react_hits = sum(
                js_lower.count(marker)
                for marker in react_markers
            )

            if react_hits >= 2:

                TechnologyDetector._add_evidence(
                    result,
                    technology="React",
                    category="JavaScript Framework",
                    confidence="High",
                    source="JavaScript Bundle",
                    evidence=(
                        f"React runtime markers detected "
                        f"in {filename}: "
                        f"matches={react_hits}"
                    )
                )

            # =================================================
            # VUE.JS
            # =================================================

            vue_markers = [
                "vue.component",
                "__vue__",
                "createapp",
                "vuex"
            ]

            vue_hits = sum(
                js_lower.count(marker)
                for marker in vue_markers
            )

            if vue_hits >= 2:

                TechnologyDetector._add_evidence(
                    result,
                    technology="Vue.js",
                    category="JavaScript Framework",
                    confidence="High",
                    source="JavaScript Bundle",
                    evidence=(
                        f"Vue runtime markers detected "
                        f"in {filename}: "
                        f"matches={vue_hits}"
                    )
                )

            # =================================================
            # JQUERY
            # =================================================

            jquery_hits = len(
                re.findall(
                    r"\bjQuery\b",
                    js,
                    re.IGNORECASE
                )
            )

            if jquery_hits >= 3:

                TechnologyDetector._add_evidence(
                    result,
                    technology="jQuery",
                    category="JavaScript Library",
                    confidence="Medium",
                    source="JavaScript Bundle",
                    evidence=(
                        f"jQuery signatures detected "
                        f"in {filename}: "
                        f"matches={jquery_hits}"
                    )
                )

            # =================================================
            # BOOTSTRAP
            # =================================================

            bootstrap_hits = js_lower.count(
                "bootstrap"
            )

            if bootstrap_hits >= 3:

                TechnologyDetector._add_evidence(
                    result,
                    technology="Bootstrap",
                    category="CSS / UI Framework",
                    confidence="Medium",
                    source="JavaScript Bundle",
                    evidence=(
                        f"Bootstrap signatures detected "
                        f"in {filename}: "
                        f"matches={bootstrap_hits}"
                    )
                )

        except requests.RequestException:
            return

        except Exception:
            return

    # =====================================================
    # FRAMEWORK SELECTION
    # =====================================================

    @staticmethod
    def _set_framework(
        result
    ):

        framework_priority = [
            "Angular",
            "React",
            "Vue.js",
            "WordPress",
            "Django",
            "Laravel",
            "Express",
            "ASP.NET"
        ]

        detected = {
            item["name"]
            for item in result["Technologies"]
        }

        for framework in framework_priority:

            if framework in detected:

                result["Framework"] = framework

                return

    # =====================================================
    # EVIDENCE + DEDUPLICATION
    # =====================================================

    @staticmethod
    def _add_evidence(
        result,
        technology,
        category,
        confidence,
        source,
        evidence
    ):

        # -------------------------------------------------
        # Technology deduplication
        # -------------------------------------------------

        existing_names = {
            item["name"]
            for item in result["Technologies"]
        }

        if technology not in existing_names:

            result["Technologies"].append(
                {
                    "name": technology,
                    "category": category,
                    "confidence": confidence
                }
            )

        # -------------------------------------------------
        # Evidence deduplication
        # -------------------------------------------------

        evidence_key = (
            technology,
            source,
            evidence
        )

        existing_evidence = {
            (
                item.get("technology"),
                item.get("source"),
                item.get("evidence")
            )
            for item in result["Evidence"]
        }

        if evidence_key not in existing_evidence:

            result["Evidence"].append(
                {
                    "technology": technology,
                    "source": source,
                    "evidence": evidence,
                    "confidence": confidence
                }
            )