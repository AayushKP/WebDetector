import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


def fetch_html(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)

        return response.text
    except:
        return ""


def detect_login_form(soup):
    if not soup:
        return 0

    for form in soup.find_all("form"):
        inputs = form.find_all("input")

        has_password = False
        has_username = False

        for inp in inputs:
            input_type = (inp.get("type") or "").lower()
            name = (inp.get("name") or "").lower()
            placeholder = (inp.get("placeholder") or "").lower()

            # detect password
            if input_type == "password":
                has_password = True

            # detect username/email fields
            if input_type in ["text", "email"]:
                if any(k in name or k in placeholder for k in ["user", "email", "login"]):
                    has_username = True

        if has_password:
            return 1  # strong signal

        if has_username and len(inputs) <= 5:
            return 1  # weak login form

    return 0


def extract_root_domain(domain):
    """Normalize domain (remove www)"""
    if domain.startswith("www."):
        return domain[4:]
    return domain


def external_links_ratio(soup, base_url):
    if not soup:
        return 0

    anchors = soup.find_all("a")

    base_domain = extract_root_domain(urlparse(base_url).netloc)

    external = 0
    valid_links = 0

    for a in anchors:
        href = a.get("href")

        if not href:
            continue

        href = href.strip().lower()

        # ❌ skip useless links
        if href.startswith("#") or \
           href.startswith("javascript:") or \
           href.startswith("mailto:") or \
           href.startswith("tel:"):
            continue

        try:
            full_url = urljoin(base_url, href)
            domain = urlparse(full_url).netloc

            if not domain:
                continue

            domain = extract_root_domain(domain)

            valid_links += 1

            if domain != base_domain:
                external += 1

        except:
            continue

    if valid_links == 0:
        return 0

    return external / valid_links


def detect_redirect(html):
    soup = BeautifulSoup(html, "html.parser")
    meta = soup.find("meta", attrs={"http-equiv": "refresh"})
    return 1 if meta else 0


def count_inputs(soup):
    return len(soup.find_all("input"))


def count_passwords(soup):
    return len(soup.find_all('input', {'type': 'password'}))


def detect_obfuscated_js(soup):
    if not soup:
        return 0

    scripts = soup.find_all("script")
    score = 0

    suspicious_patterns = [
        "eval(",
        "unescape(",
        "atob(",
        "Function(",
        "setTimeout(",
        "setInterval(",
        "decodeURIComponent("
    ]

    for script in scripts:
        # safer extraction
        content = script.get_text() or ""
        content = content.lower()

        if not content.strip():
            continue

        # pattern-based detection
        for pattern in suspicious_patterns:
            if pattern in content:
                score += 1

        # base64-like long strings
        if len(content) > 200:
            long_tokens = [tok for tok in content.split() if len(tok) > 50]
            if any(all(c.isalnum() or c in "+/=" for c in tok) for tok in long_tokens):
                score += 1

        # excessive encoding (%xx patterns)
        if content.count('%') > 30:
            score += 1

        # suspicious entropy-like structure
        if len(content) > 300 and content.count(';') > 80:
            score += 1

    return min(score, 10)  # ✅ cap to avoid explosion