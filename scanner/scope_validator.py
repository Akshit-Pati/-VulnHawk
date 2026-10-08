from urllib.parse import urlparse


class ScopeValidator:
    """
    VulnHawk Target Scope Validator.

    Determines whether a discovered endpoint belongs to the
    same origin as the authorized scan target.
    """

    @staticmethod
    def normalize_origin(url):
        parsed = urlparse(url)

        if not parsed.scheme or not parsed.hostname:
            return None

        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower()

        # Use explicit port when supplied.
        port = parsed.port

        if port:
            return scheme, hostname, port

        # Default ports.
        if scheme == "https":
            return scheme, hostname, 443

        if scheme == "http":
            return scheme, hostname, 80

        return scheme, hostname, None

    @classmethod
    def is_same_origin(cls, target, endpoint_url):
        """
        Return True when target and endpoint use the same
        scheme, hostname and effective port.
        """

        target_origin = cls.normalize_origin(target)
        endpoint_origin = cls.normalize_origin(endpoint_url)

        if not target_origin or not endpoint_origin:
            return False

        return target_origin == endpoint_origin

    @classmethod
    def validate_endpoint(cls, target, endpoint_url):
        """
        Return structured scope validation evidence.
        """

        target_origin = cls.normalize_origin(target)
        endpoint_origin = cls.normalize_origin(endpoint_url)

        same_origin = (
            target_origin is not None
            and endpoint_origin is not None
            and target_origin == endpoint_origin
        )

        return {
            "target": target,
            "endpoint": endpoint_url,
            "in_scope": same_origin,
            "target_origin": target_origin,
            "endpoint_origin": endpoint_origin
        }