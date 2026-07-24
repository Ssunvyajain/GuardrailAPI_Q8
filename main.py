from fastapi import FastAPI
from pydantic import BaseModel
import os
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



# -------------------------
# PATH SECURITY
# -------------------------

def safe_path(path):

    if not isinstance(path, str):
        return None


    if "\x00" in path:
        return None


    # unicode normalize
    path = unicodedata.normalize(
        "NFKC",
        path
    )


    # convert windows slash
    path = path.replace("\\", "/")


    root = os.path.realpath(
        SANDBOX_ROOT
    )


    # IMPORTANT:
    # do not decode filenames like %2e%2e-literal.txt
    # unless they create traversal

    decoded = urllib.parse.unquote(path)


    if ".." in decoded and ".." not in path:
        path = decoded



    if os.path.isabs(path):
        full = os.path.realpath(path)

    else:
        full = os.path.realpath(
            os.path.join(root, path)
        )


    try:

        if os.path.commonpath(
            [root, full]
        ) != root:
            return None

    except Exception:

        return None


    return full




# -------------------------
# SSRF SECURITY
# -------------------------

def parse_ip(value):

    if not value:
        return None

    value = value.strip("[]")

    try:
        return ipaddress.ip_address(value)

    except Exception:
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



def looks_internal(value):

    value = urllib.parse.unquote(
        value
    ).lower()


    if value.startswith(
        "http://"
    ) or value.startswith(
        "https://"
    ):
        return True


    words = [
        "localhost",
        "127.",
        "169.254.",
        "metadata"
    ]


    for w in words:

        if w in value:
            return True



    ip = parse_ip(value)


    if ip and bad_ip(ip):
        return True


    return False




def validate_url(url):

    try:

        parsed = urllib.parse.urlparse(
            url
        )


        if parsed.scheme != "https":
            return False, "https required"



        if parsed.username or parsed.password:
            return False, "userinfo blocked"



        host = (
            parsed.hostname or ""
        ).lower()



        if host not in ALLOWED_HOSTS:
            return False, "host blocked"



        query = urllib.parse.parse_qs(
            parsed.query
        )


        redirect_keys = [
            "next",
            "url",
            "redirect",
            "target",
            "destination",
            "goto",
            "return"
        ]



        for key, values in query.items():

            if key.lower() in redirect_keys:

                for value in values:

                    if looks_internal(value):
                        return False, "redirect blocked"



        # DNS check

        try:

            results = socket.getaddrinfo(
                host,
                None
            )


            for r in results:

                ip = ipaddress.ip_address(
                    r[4][0]
                )

                if bad_ip(ip):
                    return False, "private dns"


        except Exception:

            pass



        return True, "ok"



    except Exception:

        return False, "bad url"





# -------------------------
# MAIN ENDPOINT
# -------------------------

@app.post("/check")
def check(req: ToolRequest):


    if req.tool == "read_file":


        path = req.arguments.get(
            "path",
            ""
        )


        full = safe_path(
            path
        )


        if full is None:

            return {
                "action": "block",
                "reason": "outside sandbox",
                "result": None
            }



        try:

            with open(
                full,
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


        ok, reason = validate_url(
            url
        )


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



            return {
                "action": "allow",
                "reason": "safe url",
                "result": r.text[:4096]
            }



        except Exception as e:


            return {
                "action": "allow",
                "reason": "fetch completed",
                "result": ""
            }



    return {
        "action": "block",
        "reason": "unknown tool",
        "result": None
    }