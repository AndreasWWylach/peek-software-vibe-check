import requests
from urllib.parse import urlparse

BLOCKED = ("localhost", "169.254.169.254")


def profile(request):
    # OWN api with a literal host — the id is path data, not the destination.
    return requests.get(f"https://api.example.com/users/{request.args.get('id')}").text


def preview(request):
    # Request URL is validated before any fetch.
    target = request.args.get("url")
    parsed = urlparse(target)
    if parsed.scheme != "https" or parsed.hostname in BLOCKED:
        return "rejected"
    return requests.get(target).text


def status():
    return requests.get("https://api.example.com/status").text
