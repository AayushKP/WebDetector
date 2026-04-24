import socket
import ssl
from datetime import datetime
import whois
from urllib.parse import urlparse
import ipaddress


# ---------- DOMAIN ----------
def extract_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path

    # remove port if present
    domain = domain.split(":")[0]

    # remove www
    if domain.startswith("www."):
        domain = domain[4:]

    return domain.lower()


def is_ip(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except:
        return False


# ---------- WHOIS HELPERS ----------
def safe_get(w, key):
    """Handles both dict and object responses"""
    if isinstance(w, dict):
        return w.get(key)
    return getattr(w, key, None)


def normalize_date(value):
    """Handle list + timezone issues"""
    if isinstance(value, list):
        value = value[0]

    if value is None:
        return None

    # Convert timezone-aware → naive
    if hasattr(value, "tzinfo") and value.tzinfo is not None:
        value = value.replace(tzinfo=None)

    return value


def get_whois_data(domain):
    """Single WHOIS call (avoid rate limits)"""
    try:
        return whois.whois(domain)
    except Exception as e:
        print(f"WHOIS fetch error: {e}")
        return None


# ---------- WHOIS FEATURES ----------
def get_domain_age(domain, w=None):
    try:
        if is_ip(domain):
            return -1

        if w is None:
            w = get_whois_data(domain)

        if not w:
            return -1

        creation_date = normalize_date(safe_get(w, "creation_date"))

        if creation_date:
            now = datetime.utcnow()  # ✅ BOTH NAIVE
            return max((now - creation_date).days,0)

    except Exception as e:
        print(f"WHOIS age error: {e}")

    return -1


def get_expiry(domain, w=None):
    try:
        if is_ip(domain):
            return -1

        if w is None:
            w = get_whois_data(domain)

        if not w:
            return -1

        expiry_date = normalize_date(safe_get(w, "expiration_date"))

        if expiry_date:
            now = datetime.utcnow()  # ✅ BOTH NAIVE
            return max((expiry_date - now).days,0)

    except Exception as e:
        print(f"WHOIS expiry error: {e}")

    return -1


def has_whois(domain, w=None):
    try:
        if is_ip(domain):
            return False

        if w is None:
            w = get_whois_data(domain)

        if not w:
            return False

        creation_date = safe_get(w, "creation_date")
        return creation_date is not None

    except:
        return False


# ---------- DNS ----------
def has_dns(domain):
    if is_ip(domain):
        return 1  # IP always resolves

    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False
    except:
        return False


# ---------- SSL ----------
def check_ssl(domain):
    if not domain or is_ip(domain):
        return 0

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return int(bool(cert))
    except:
        return 0


def get_cert_duration(domain):
    if not domain or is_ip(domain):
        return -1

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                not_before = datetime.strptime(
                    cert['notBefore'], "%b %d %H:%M:%S %Y %Z"
                )
                not_after = datetime.strptime(
                    cert['notAfter'], "%b %d %H:%M:%S %Y %Z"
                )

                return max((not_after - not_before).days, 0)

    except Exception as e:
        print(f"SSL error: {e}")
        return -1


# ---------- HEURISTICS ----------
def reputation_score(domain):
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return 1
    return 0


def geo_risk(domain):
    high_risk_regions = ["ru", "cn", "kp"]

    for region in high_risk_regions:
        if domain.endswith("." + region):
            return 1
    return 0