from fastapi import FastAPI
from pydantic import BaseModel
import os
from urllib.parse import urlparse, parse_qs
import requests
import ipaddress

app = FastAPI()


SANDBOX_ROOT = "/srv/agent-redteam/sandbox-4f1ea4cb0b"

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


def resolves_inside(path, root):
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(root, path))

    root = os.path.normpath(root)

    return full == root or full.startswith(root + os.sep)


def looks_like_internal_target(value):

    value = value.lower()

    if "localhost" in value:
        return True

    if "127.0.0.1" in value:
        return True

    if "169.254." in value:
        return True

    if "http://" in value or "https://" in value:
        try:
            host = urlparse(value).hostname
            if host:
                ip = ipaddress.ip_address(host)
                if ip.is_private or ip.is_loopback:
                    return True
        except:
            pass

    return False



@app.get("/")
def home():
    return {
        "message": "Guardrail API Running"
    }



@app.post("/check")
def check(req: ToolRequest):

    tool = req.tool
    args = req.arguments


    # FILE TOOL
    if tool == "read_file":

        path = args.get("path", "")

        if not resolves_inside(path, SANDBOX_ROOT):

            return {
                "action":"block",
                "reason":"Path escapes sandbox"
            }


        try:
            with open(path,"r") as f:
                data=f.read()

            return {
                "action":"allow",
                "reason":"Safe sandbox path",
                "result":data
            }

        except Exception as e:

            return {
                "action":"allow",
                "reason":"File allowed but unavailable",
                "result":str(e)
            }



    # NETWORK TOOL
    if tool == "fetch_url":

        url=args.get("url","")

        u=urlparse(url)

        host=(u.hostname or "").lower()


        if host not in ALLOWED_HOSTS:

            return {
                "action":"block",
                "reason":"Host not allowed"
            }


        for values in parse_qs(u.query).values():

            for v in values:

                if looks_like_internal_target(v):

                    return {
                        "action":"block",
                        "reason":"Possible SSRF attempt"
                    }


        try:

            r=requests.get(url,timeout=5)

            return {
                "action":"allow",
                "reason":"Allowed host",
                "result":r.text[:500]
            }


        except Exception as e:

            return {
                "action":"allow",
                "reason":"Request failed",
                "result":str(e)
            }



    return {
        "action":"block",
        "reason":"Unknown tool"
    }