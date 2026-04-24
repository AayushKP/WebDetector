import ipaddress
import math
from urllib.parse import urlparse

def is_ip_address(url):
    try:
        host = urlparse(url).netloc
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def count_subdomains(url):
    netloc = urlparse(url).netloc

    try:
        ipaddress.ip_address(netloc)
        return 0
    except:
        pass

    parts = netloc.split('.')
    return max(len(parts) - 2, 0)


def compute_entropy(url):
    # Shannon entropy
    if not url:
        return 0
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    entropy = -sum(p * math.log2(p) for p in prob)
    return entropy


def keyword_score(url):
    suspicious_keywords = [
        "login", "secure", "account", "update", "verify",
        "bank", "paypal", "signin", "confirm", "password",
        "ebay", "amazon", "free", "bonus", "win"
    ]
    url_lower = url.lower()
    score = sum(1 for word in suspicious_keywords if word in url_lower)
    return score


def brand_distance(url):
    # simple heuristic: check similarity to popular brands
    brands = ["google", "facebook", "amazon", "paypal", "apple", "microsoft"]

    def levenshtein(a, b):
        dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
        for i in range(len(a) + 1):
            dp[i][0] = i
        for j in range(len(b) + 1):
            dp[0][j] = j

        for i in range(1, len(a) + 1):
            for j in range(1, len(b) + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                dp[i][j] = min(
                    dp[i - 1][j] + 1,
                    dp[i][j - 1] + 1,
                    dp[i - 1][j - 1] + cost
                )
        return dp[-1][-1]

    domain = urlparse(url).netloc.lower()

    min_distance = float('inf')
    for brand in brands:
        dist = levenshtein(domain, brand)
        min_distance = min(min_distance, dist)

    return min_distance


def tld_score(url):
    # risky TLDs often used in phishing
    risky_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"]

    netloc = urlparse(url).netloc.lower()

    for tld in risky_tlds:
        if netloc.endswith(tld):
            return 1
    return 0