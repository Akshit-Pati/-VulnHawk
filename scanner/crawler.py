import re
import requests

from urllib.parse import (
    urljoin,
    urlparse,
    parse_qsl
)

from scanner.scope_validator import ScopeValidator


class WebCrawler:

    USER_AGENT = "VulnHawk/1.0 Security Scanner"

    # =================================================
    # URL NORMALIZATION
    # =================================================

    @staticmethod
    def normalize_endpoint(url):

        try:
            parsed = urlparse(url)

            if not parsed.scheme or not parsed.hostname:
                return None

            path = parsed.path or "/"

            return parsed._replace(
                path=path,
                fragment=""
            ).geturl()

        except Exception:
            return None

    # =================================================
    # ENDPOINT PATH
    # =================================================

    @staticmethod
    def endpoint_path(url):

        try:
            parsed = urlparse(url)
            return parsed.path or "/"

        except Exception:
            return "/"

    # =================================================
    # PARAMETER VALIDATION
    # =================================================

    @staticmethod
    def is_valid_parameter_name(name):

        if not name:
            return False

        name = name.strip()

        if len(name) > 64:
            return False

        return bool(
            re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_.-]*",
                name
            )
        )

    # =================================================
    # QUERY PARAMETER EXTRACTION
    # =================================================

    @classmethod
    def extract_parameters(cls, url):

        parameters = set()

        try:

            parsed = urlparse(url)

            for key, _ in parse_qsl(
                parsed.query,
                keep_blank_values=True
            ):

                key = key.strip()

                if not cls.is_valid_parameter_name(
                    key
                ):
                    continue

                parameters.add(key)

        except Exception:
            pass

        return parameters


        # =================================================
    # STATIC RESOURCE VALIDATION
    # =================================================

    @staticmethod
    def is_static_resource(endpoint):

        if not endpoint:
            return True

        try:
            path = urlparse(endpoint).path.lower()
        except Exception:
            return True

        static_extensions = (
            ".js",
            ".css",
            ".map",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".ico",
            ".webp",
            ".avif",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".otf",
            ".mp3",
            ".wav",
            ".mp4",
            ".webm",
            ".avi",
            ".mov",
            ".pdf",
            ".zip",
            ".gz",
            ".tar",
            ".rar",
            ".7z",
        )

        return path.endswith(
            static_extensions
        )


    # =================================================
    # JAVASCRIPT ENDPOINT VALIDATION
    # =================================================

    @staticmethod
    def is_valid_js_endpoint(endpoint):

        if not endpoint:
            return False

        endpoint = endpoint.strip()

        if not endpoint.startswith("/"):
            return False

        if endpoint.startswith("//"):
            return False

        # Remove query for path validation
        path = endpoint.split("?", 1)[0]

        # Reject numeric-only paths
        if re.fullmatch(
            r"/\d+/?",
            path
        ):
            return False

        # Must contain at least one alphabetic character
        if not re.search(
            r"[A-Za-z]",
            path
        ):
            return False

        # Reject static resources
        static_extensions = (
            ".js",
            ".css",
            ".map",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".ico",
            ".webp",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".mp3",
            ".mp4",
            ".webm",
            ".pdf"
        )

        if path.lower().endswith(
            static_extensions
        ):
            return False

        if len(endpoint) > 300:
            return False

        return True

    # =================================================
    # JAVASCRIPT ENDPOINT EXTRACTION
    # =================================================

    @classmethod
    def extract_js_endpoints(cls, js_content):

        endpoints = set()

        if not js_content:
            return endpoints

        patterns = [

            # API / REST / versioned routes
            r"""
            ["']
            (
                /
                (?:
                    api
                    |
                    rest
                    |
                    v[0-9]+
                    |
                    graphql
                    |
                    auth
                )
                /
                [A-Za-z0-9_./?=&:%@+\-]+
            )
            ["']
            """,

            # Common application routes
            r"""
            ["']
            (
                /
                (?:
                    login
                    |
                    logout
                    |
                    register
                    |
                    search
                    |
                    profile
                    |
                    account
                    |
                    admin
                    |
                    user
                    |
                    users
                    |
                    basket
                    |
                    cart
                    |
                    orders?
                    |
                    payment
                    |
                    upload
                    |
                    download
                    |
                    contact
                    |
                    forgot-password
                    |
                    reset-password
                    |
                    dashboard
                    |
                    settings
                    |
                    reviews?
                    |
                    products?
                )
                (?:
                    /
                    [A-Za-z0-9_.?=&:%@+\-]+
                )?
            )
            ["']
            """,

            # Generic multi-level application paths
            r"""
            ["']
            (
                /
                [A-Za-z][A-Za-z0-9_-]*
                /
                [A-Za-z0-9_.?=&:%@+\-]+
                (?:
                    /
                    [A-Za-z0-9_.?=&:%@+\-]+
                )*
            )
            ["']
            """
        ]

        for pattern in patterns:

            try:

                matches = re.findall(
                    pattern,
                    js_content,
                    flags=re.IGNORECASE |
                    re.VERBOSE
                )

                for endpoint in matches:

                    endpoint = endpoint.strip()

                    if not cls.is_valid_js_endpoint(
                        endpoint
                    ):
                        continue

                    if (
                        endpoint != "/"
                        and endpoint.endswith("/")
                    ):
                        endpoint = endpoint[:-1]

                    endpoints.add(
                        endpoint
                    )

            except Exception:
                continue

        return endpoints

    # =================================================
    # SCOPE VALIDATION
    # =================================================

    @staticmethod
    def is_in_scope(
        target,
        endpoint
    ):

        try:

            return ScopeValidator.is_same_origin(
                target,
                endpoint
            )

        except Exception:
            return False

    # =================================================
    # REGISTER ENDPOINT
    # =================================================

    @classmethod
    def register_endpoint(
        cls,
        endpoint,
        endpoints,
        parameters,
        parameter_map
    ):

        normalized = cls.normalize_endpoint(
            endpoint
        )

        if not normalized:
            return

        if not cls.is_in_scope(
            endpoints.get(
                "__target__",
                normalized
            )
            if isinstance(endpoints, dict)
            else normalized,
            normalized
        ):
            pass

        endpoints.add(
            normalized
        )

        endpoint_parameters = (
            cls.extract_parameters(
                normalized
            )
        )

        if not endpoint_parameters:
            return

        path = cls.endpoint_path(
            normalized
        )

        if path not in parameter_map:
            parameter_map[path] = set()

        for parameter in endpoint_parameters:

            if not cls.is_valid_parameter_name(
                parameter
            ):
                continue

            parameters.add(
                parameter
            )

            parameter_map[path].add(
                parameter
            )

    # =================================================
    # REGISTER PARAMETER
    # =================================================

    @classmethod
    def register_parameter(
        cls,
        endpoint,
        parameter,
        parameters,
        parameter_map
    ):

        if not cls.is_valid_parameter_name(
            parameter
        ):
            return

        normalized = cls.normalize_endpoint(
            endpoint
        )

        if not normalized:
            return

        path = cls.endpoint_path(
            normalized
        )

        parameters.add(
            parameter
        )

        if path not in parameter_map:
            parameter_map[path] = set()

        parameter_map[path].add(
            parameter
        )

    # =================================================
    # HTML LINK EXTRACTION
    # =================================================

    @staticmethod
    def extract_links(html):

        links = set()

        if not html:
            return links

        pattern = re.compile(
            r'<a\b[^>]*?\bhref\s*=\s*'
            r'["\']([^"\']+)["\']',
            re.IGNORECASE
        )

        for match in pattern.finditer(html):

            href = match.group(1).strip()

            if href:
                links.add(href)

        return links

    # =================================================
    # SCRIPT SOURCE EXTRACTION
    # =================================================

    @staticmethod
    def extract_script_sources(html):

        sources = set()

        if not html:
            return sources

        pattern = re.compile(
            r'<script\b([^>]*)>',
            re.IGNORECASE
        )

        for match in pattern.finditer(html):

            attributes = match.group(1)

            src_match = re.search(
                r'\bsrc\s*=\s*["\']([^"\']+)["\']',
                attributes,
                re.IGNORECASE
            )

            if not src_match:
                continue

            src = src_match.group(1).strip()

            if src:
                sources.add(src)

        return sources

    # =================================================
    # FORM DISCOVERY
    # =================================================

    @classmethod
    def extract_forms(
        cls,
        html,
        current_url,
        target,
        parameters,
        parameter_map
    ):

        forms = []

        if not html:
            return forms

        form_pattern = re.compile(
            r"<form\b([^>]*)>(.*?)</form>",
            re.IGNORECASE |
            re.DOTALL
        )

        input_pattern = re.compile(
            r"<(?:input|textarea|select)\b([^>]*)>",
            re.IGNORECASE
        )

        for form_match in form_pattern.finditer(
            html
        ):

            attributes = form_match.group(1)

            body = form_match.group(2)

            # -----------------------------------------
            # Method
            # -----------------------------------------

            method_match = re.search(
                r'\bmethod\s*=\s*["\']([^"\']+)["\']',
                attributes,
                re.IGNORECASE
            )

            method = (
                method_match.group(1).upper()
                if method_match
                else "GET"
            )

            # -----------------------------------------
            # Action
            # -----------------------------------------

            action_match = re.search(
                r'\baction\s*=\s*["\']([^"\']+)["\']',
                attributes,
                re.IGNORECASE
            )

            if action_match:
                action = action_match.group(1)
            else:
                action = current_url

            action_url = urljoin(
                current_url,
                action
            )

            action_url = cls.normalize_endpoint(
                action_url
            )

            if not action_url:
                continue

            if not cls.is_in_scope(
                target,
                action_url
            ):
                continue

            # -----------------------------------------
            # Inputs
            # -----------------------------------------

            input_names = set()

            for input_match in input_pattern.finditer(
                body
            ):

                input_attributes = (
                    input_match.group(1)
                )

                name_match = re.search(
                    r'\bname\s*=\s*["\']([^"\']+)["\']',
                    input_attributes,
                    re.IGNORECASE
                )

                if not name_match:
                    continue

                name = name_match.group(1).strip()

                if not cls.is_valid_parameter_name(
                    name
                ):
                    continue

                input_names.add(
                    name
                )

            # -----------------------------------------
            # Register form parameters
            # -----------------------------------------

            for name in input_names:

                cls.register_parameter(
                    action_url,
                    name,
                    parameters,
                    parameter_map
                )

            forms.append(
                {
                    "url": action_url,
                    "method": method,
                    "parameters": sorted(
                        input_names
                    )
                }
            )

        return forms

    # =================================================
    # MAIN CRAWLER
    # =================================================

    @classmethod
    def crawl(
        cls,
        target,
        max_pages=20,
        max_depth=2,
        timeout=10
    ):

        target = target.strip()

        if not target.startswith(
            (
                "http://",
                "https://"
            )
        ):
            target = "https://" + target

        target = target.rstrip("/")

        # ---------------------------------------------
        # Validate target
        # ---------------------------------------------

        try:

            parsed_target = urlparse(
                target
            )

            if not parsed_target.hostname:
                raise ValueError(
                    "Invalid target URL"
                )

        except Exception as error:

            return {
                "target": target,
                "pages_crawled": 0,
                "pages": [],
                "parameters": [],
                "parameter_map": {},
                "forms": [],
                "javascript_files": [],
                "javascript_endpoints": [],
                "endpoints": [],
                "errors": [
                    {
                        "url": target,
                        "error": str(error)
                    }
                ]
            }

        # ---------------------------------------------
        # Containers
        # ---------------------------------------------

        visited = set()
        discovered = []

        parameters = set()
        parameter_map = {}

        forms = []

        javascript_files = set()
        javascript_endpoints = set()

        endpoints = set()

        errors = []

        # ---------------------------------------------
        # Queue
        # ---------------------------------------------

        queue = [
            (
                target,
                0
            )
        ]

        # ---------------------------------------------
        # HTTP session
        # ---------------------------------------------

        session = requests.Session()

        session.headers.update(
            {
                "User-Agent": cls.USER_AGENT,
                "Accept": "*/*"
            }
        )

        # ---------------------------------------------
        # Crawl loop
        # ---------------------------------------------

        while queue:

            current_url, depth = queue.pop(0)

            if len(visited) >= max_pages:
                break

            if depth > max_depth:
                continue

            normalized_current = (
                cls.normalize_endpoint(
                    current_url
                )
            )

            if not normalized_current:
                continue

            if not cls.is_in_scope(
                target,
                normalized_current
            ):
                continue

            if normalized_current in visited:
                continue

            visited.add(
                normalized_current
            )

            # -----------------------------------------
            # Register current endpoint
            # -----------------------------------------

            endpoints.add(
                normalized_current
            )

            current_parameters = (
                cls.extract_parameters(
                    normalized_current
                )
            )

            for parameter in current_parameters:

                cls.register_parameter(
                    normalized_current,
                    parameter,
                    parameters,
                    parameter_map
                )

            # -----------------------------------------
            # Request
            # -----------------------------------------

            try:

                response = session.get(
                    normalized_current,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False
                )

            except requests.RequestException as error:

                errors.append(
                    {
                        "url": normalized_current,
                        "error": str(error)
                    }
                )

                continue

            except Exception as error:

                errors.append(
                    {
                        "url": normalized_current,
                        "error": str(error)
                    }
                )

                continue

            # -----------------------------------------
            # Redirect scope
            # -----------------------------------------

            final_url = cls.normalize_endpoint(
                response.url
            )

            if (
                final_url
                and
                not cls.is_in_scope(
                    target,
                    final_url
                )
            ):

                errors.append(
                    {
                        "url": normalized_current,
                        "error": (
                            "Redirected outside "
                            "target scope"
                        )
                    }
                )

                continue

            # -----------------------------------------
            # Content type
            # -----------------------------------------

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            discovered.append(
                {
                    "url": normalized_current,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "depth": depth
                }
            )

            # -----------------------------------------
            # HTML only
            # -----------------------------------------

            if "text/html" not in content_type:
                continue

            html = response.text

            # =================================================
            # FORM DISCOVERY
            # =================================================

            discovered_forms = cls.extract_forms(
                html,
                normalized_current,
                target,
                parameters,
                parameter_map
            )

            forms.extend(
                discovered_forms
            )

            # =================================================
            # JAVASCRIPT DISCOVERY
            # =================================================

            script_sources = (
                cls.extract_script_sources(
                    html
                )
            )

            for src in script_sources:

                js_url = urljoin(
                    normalized_current,
                    src
                )

                js_url = cls.normalize_endpoint(
                    js_url
                )

                if not js_url:
                    continue

                if not cls.is_in_scope(
                    target,
                    js_url
                ):
                    continue

                javascript_files.add(
                    js_url
                )

                try:

                    js_response = session.get(
                        js_url,
                        timeout=timeout,
                        allow_redirects=True,
                        verify=False
                    )

                except requests.RequestException as error:

                    errors.append(
                        {
                            "url": js_url,
                            "error": str(error)
                        }
                    )

                    continue

                except Exception as error:

                    errors.append(
                        {
                            "url": js_url,
                            "error": str(error)
                        }
                    )

                    continue

                if js_response.status_code != 200:
                    continue

                js_content = js_response.text

                # -----------------------------------------
                # JS endpoints ONLY
                # -----------------------------------------

                js_routes = (
                    cls.extract_js_endpoints(
                        js_content
                    )
                )

                for js_endpoint in js_routes:

                    absolute_endpoint = urljoin(
                        normalized_current,
                        js_endpoint
                    )

                    absolute_endpoint = (
                        cls.normalize_endpoint(
                            absolute_endpoint
                        )
                    )

                    if not absolute_endpoint:
                        continue

                    if not cls.is_in_scope(
                        target,
                        absolute_endpoint
                    ):
                        continue

                    javascript_endpoints.add(
                        cls.endpoint_path(
                            absolute_endpoint
                        )
                    )

                    endpoints.add(
                        absolute_endpoint
                    )

                    # -------------------------------------
                    # If JS route itself contains a query
                    # parameter, that is valid evidence.
                    # -------------------------------------

                    js_parameters = (
                        cls.extract_parameters(
                            absolute_endpoint
                        )
                    )

                    for parameter in js_parameters:

                        cls.register_parameter(
                            absolute_endpoint,
                            parameter,
                            parameters,
                            parameter_map
                        )

            # =================================================
            # HTML LINK DISCOVERY
            # =================================================

            links = cls.extract_links(
                html
            )

            for href in links:

                lowered = href.lower()

                if lowered.startswith(
                    (
                        "javascript:",
                        "mailto:",
                        "tel:",
                        "data:",
                        "blob:"
                    )
                ):
                    continue

                if href.startswith("#"):
                    continue

                absolute_url = urljoin(
                    normalized_current,
                    href
                )

                normalized_link = (
                    cls.normalize_endpoint(
                        absolute_url
                    )
                )

                if not normalized_link:
                    continue

                if not cls.is_in_scope(
                    target,
                    normalized_link
                ):
                    continue

                path = cls.endpoint_path(
                    normalized_link
                ).lower()

                # -----------------------------------------
                # Static resources
                # -----------------------------------------

                if path.endswith(
                    (
                        ".js",
                        ".css",
                        ".png",
                        ".jpg",
                        ".jpeg",
                        ".gif",
                        ".svg",
                        ".ico",
                        ".webp",
                        ".woff",
                        ".woff2",
                        ".ttf",
                        ".eot",
                        ".mp3",
                        ".mp4",
                        ".webm",
                        ".pdf"
                    )
                ):
                    continue

                # -----------------------------------------
                # Register
                # -----------------------------------------

                endpoints.add(
                    normalized_link
                )

                link_parameters = (
                    cls.extract_parameters(
                        normalized_link
                    )
                )

                for parameter in link_parameters:

                    cls.register_parameter(
                        normalized_link,
                        parameter,
                        parameters,
                        parameter_map
                    )

                # -----------------------------------------
                # Queue
                # -----------------------------------------

                if (
                    normalized_link not in visited
                    and len(queue) < max_pages
                ):

                    queue.append(
                        (
                            normalized_link,
                            depth + 1
                        )
                    )

        # =================================================
        # CLEAN PARAMETER MAP
        # =================================================

        clean_parameter_map = {}

        for endpoint_path, values in (
            parameter_map.items()
        ):

            parsed_path = urlparse(
                endpoint_path
            ).path or "/"

            if not parsed_path.startswith("/"):
                parsed_path = "/" + parsed_path

            clean_values = sorted(
                {
                    value.strip()
                    for value in values
                    if cls.is_valid_parameter_name(
                        value
                    )
                }
            )

            if clean_values:

                clean_parameter_map[
                    parsed_path
                ] = clean_values

        # =================================================
        # CLEAN JAVASCRIPT ENDPOINTS
        # =================================================

        clean_js_endpoints = sorted(
            {
                endpoint
                for endpoint in javascript_endpoints
                if cls.is_valid_js_endpoint(
                    endpoint
                )
            }
        )

        # =================================================
        # CLEAN ENDPOINTS
        # =================================================
        #
        # Keep endpoint identity separate from query
        # parameters. Example:
        #
        #   /rest/user/security-question?email=
        #
        # becomes:
        #
        #   /rest/user/security-question
        #
        # The "email" parameter remains in parameter_map.
        # This prevents duplicate endpoint identities and
        # gives XSS/SQLi/future scanners a stable target.
        # =================================================

        canonical_endpoints = set()

        for endpoint in endpoints:

            normalized = cls.normalize_endpoint(
                endpoint
            )

            if not normalized:
                continue

            if not cls.is_in_scope(
                target,
                normalized
            ):
                continue

            if cls.is_static_resource(
                normalized
            ):
                continue

            if len(normalized) > 300:
                continue

            parsed = urlparse(
                normalized
            )

            canonical = parsed._replace(
                query="",
                fragment=""
            ).geturl()

            canonical = cls.normalize_endpoint(
                canonical
            )

            if not canonical:
                continue

            canonical_endpoints.add(
                canonical
            )

        clean_endpoints = sorted(
            canonical_endpoints
        )

        # =================================================
        # FINAL RESULT
        # =================================================

        return {
            "target": target,

            "pages_crawled": len(
                visited
            ),

            "pages": discovered,

            "parameters": sorted(
                parameters
            ),

            "parameter_map": (
                clean_parameter_map
            ),

            "forms": forms,

            "javascript_files": sorted(
                javascript_files
            ),

            "javascript_endpoints": (
                clean_js_endpoints
            ),

            "endpoints": clean_endpoints,

            "errors": errors
        }