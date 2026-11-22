import requests
import httpx
import urllib.request


def proxy(request):
    return requests.get(request.args.get("url")).text


def preview(request):
    return httpx.post(request.form["callback"]).text


def fetch_remote(request):
    return urllib.request.urlopen(request.args["target"]).read()
