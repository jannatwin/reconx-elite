import re
from typing import List
from urllib.parse import urlparse


def classify_endpoint(url: str) -> str:
    """Classify endpoint into categories: API, login, admin, static."""
    parsed = urlparse(url.lower())
    path = parsed.path
    query = parsed.query

    # API endpoints
    if re.search(r'/api/|/v\d+/|/graphql|/rest/', path) or 'api' in path:
        return 'API'

    # Login pages
    if re.search(r'/login|/signin|/auth|/oauth', path) or 'login' in query:
        return 'login'

    # Admin panels
    if re.search(r'/admin|/dashboard|/wp-admin|/administrator', path):
        return 'admin'

    # Static files
    if re.search(r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$', path):
        return 'static'

    # Default to static if no match
    return 'static'


def auto_tag_endpoint(url: str) -> List[str]:
    """Auto-tag endpoints based on patterns."""
    tags = []
    parsed = urlparse(url.lower())
    path = parsed.path
    query = parsed.query

    if 'admin' in path or 'dashboard' in path:
        tags.append('admin')
    if 'login' in path or 'auth' in path:
        tags.append('auth')
    if 'api' in path or re.search(r'/v\d+/', path):
        tags.append('api')
    if re.search(r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$', path):
        tags.append('static')
    if 'wp-' in path or 'wordpress' in path:
        tags.append('wordpress')
    if 'php' in path or '.php' in path:
        tags.append('php')

    return tags


def is_interesting_endpoint(category: str, tags: List[str]) -> bool:
    """Determine if endpoint is interesting."""
    interesting_categories = ['admin', 'login', 'API']
    interesting_tags = ['admin', 'auth', 'api']
    return category in interesting_categories or any(tag in interesting_tags for tag in tags)


def auto_tag_subdomain(hostname: str, tech_stack: List[str] = None) -> List[str]:
    """Auto-tag subdomains."""
    tags = []
    if hostname.startswith('www.'):
        tags.append('www')
    if 'api' in hostname:
        tags.append('api')
    if 'admin' in hostname:
        tags.append('admin')
    if 'dev' in hostname or 'staging' in hostname:
        tags.append('dev')
    if tech_stack:
        for tech in tech_stack:
            if 'wordpress' in tech.lower():
                tags.append('wordpress')
            if 'nginx' in tech.lower():
                tags.append('nginx')
            if 'apache' in tech.lower():
                tags.append('apache')
    return tags