# Does a saved login belong to the page the user is on?
# Anti-phishing rule: same host, or a subdomain of the saved host. Nothing looser.
from urllib.parse import urlparse


def host_of(url: str | None) -> str | None:
    # "https://www.GitHub.com/login" → "github.com". None if there's no usable host.
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host or None


def page_is_web(page_url: str | None) -> bool:
    # Only real web pages: no chrome://, file://, data:, etc.
    return bool(page_url) and urlparse(page_url).scheme in ("http", "https")


def url_matches(saved_url: str | None, page_url: str | None) -> bool:
    # saved github.com → matches github.com, gist.github.com
    # saved github.com → does NOT match githuub.com, github.com.evil.io, notgithub.com
    if not page_is_web(page_url):
        return False
    saved, page = host_of(saved_url), host_of(page_url)
    if not saved or not page:
        return False
    return page == saved or page.endswith("." + saved)
