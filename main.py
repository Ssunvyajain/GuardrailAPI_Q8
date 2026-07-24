from fastapi import FastAPI
from pydantic import BaseModel
import os
import re
import socket
import ipaddress
import urllib.parse
import unicodedata
import requests


app = FastAPI()

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-4f1ea4cb0b"

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


# -----------------------------
# PATH SECURITY
# -----------------------------

def safe_path(path):

    if not isinstance(path, str):
        return None

    if "\x00" in path or "%00" in path:
        return None

    # decode multiple times
    for _ in range(5):
        old = path
        path = urllib.parse.unquote(path)
        if old == path:
            break

    # normalize unicode
    path = unicodedata.normalize("NFKC", path)

    # windows traversal
    path = path.replace("\\", "/")

    root = os.path.realpath(SANDBOX_ROOT)

    if os.path.isabs(path):
        full = os.path.realpath(path)
    else:
        full = os.path.realpath(
            os.path.join(root, path)
        )

    try:
        if os.path.commonpath([root, full]) != root:
            return None
    except ValueError:
        return None

    return full



# -----------------------------
# SSRF SECURITY
# -----------------------------

def parse_ip(value):

    if not value:
        return None

    value = value.strip("[]")

    try:
        return ipaddress.ip_address(value)
    except:
        pass


    # decimal IP bypass
    if value.isdigit():
        try:
            return ipaddress.IPv4Address(int(value))
        except:
            pass

    return None



def bad_ip(ip):

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )



def internal_target(value):

    value = urllib.parse.unquote(value).lower()


    if value.startswith("http://") or value.startswith("https://"):
        return True


    bad_words = [
        "localhost",
        "127.",
        "169.254.",
        "metadata",
        "0.0.0.0"
    ]


    for x in bad_words:
        if x in value:
            return True


    ip = parse_ip(value)

    if ip and bad_ip(ip):
        return True


    return False



def check_url(url):

    try:

        parsed = urllib.parse.urlparse(url)


        if parsed.scheme != "https":
            return False, "only https allowed"


        if parsed.username or parsed.password:
            return False, "userinfo blocked"


        host = (parsed.hostname or "").lower()


        if host not in ALLOWED_HOSTS:
            return False, "host not allowed"



        # query redirect checks

        query = urllib.parse.parse_qs(parsed.query)

        redirect_names = [
            "next",
            "redirect",
            "url",
            "target",
            "destination",
            "return",
            "goto",
            "forward"
        ]


        for key, values in query.items():

            if key.lower() in redirect_names:

                for value in values:

                    if internal_target(value):
                        return False, "redirect SSRF blocked"



        # DNS validation

        try:

            results = socket.getaddrinfo(host, None)

            for r in results:

                ip = ipaddress.ip_address(
                    r[4][0]
                )

                if bad_ip(ip):
                    return False, "private DNS result"

        except:

            return False, "dns failure"



        return True, "ok"



    except:

        return False, "invalid url"



# -----------------------------
# ENDPOINT
# -----------------------------

@app.post("/check")
def check(req: ToolRequest):


    if req.tool == "read_file":

        path = req.arguments.get(
            "path",
            ""
        )


        real = safe_path(path)


        if real is None:

            return {
                "action": "block",
                "reason": "outside sandbox",
                "result": None
            }


        try:

            with open(
                real,
                "r",
                encoding="utf-8"
            ) as f:

                return {
                    "action": "allow",
                    "reason": "safe file",
                    "result": f.read()
                }


        except Exception as e:

            return {
                "action": "block",
                "reason": str(e),
                "result": None
            }



    elif req.tool == "fetch_url":


        url = req.arguments.get(
            "url",
            ""
        )


        ok, reason = check_url(url)


        if not ok:

            return {
                "action": "block",
                "reason": reason,
                "result": None
            }



        try:

            r = requests.get(
                url,
                timeout=5,
                allow_redirects=False
            )


            # block HTTP redirects

            if 300 <= r.status_code < 400:

                return {
                    "action": "block",
                    "reason": "redirect blocked",
                    "result": None
                }


            return {
                "action": "allow",
                "reason": "safe fetch",
                "result": r.text[:4096]
            }


        except Exception as e:

            return {
                "action": "block",
                "reason": str(e),
                "result": None
            }



    return {
        "action": "block",
        "reason": "unknown tool",
        "result": None
    }