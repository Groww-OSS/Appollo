def is_private_ip(ip: str) -> bool:
    """Check if an IPv4 address is in a private/reserved range.

    Covers RFC-1918, loopback, link-local (169.254.x.x),
    and carrier-grade NAT (100.64-127.x.x / RFC 6598).
    """
    if not ip or not isinstance(ip, str):
        return False

    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("127."):
        return True
    if ip.startswith("169.254."):
        return True

    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        first, second = int(parts[0]), int(parts[1])

        if first == 172 and 16 <= second <= 31:
            return True
        if first == 100 and 64 <= second <= 127:
            return True
    except (ValueError, IndexError):
        pass

    return False
