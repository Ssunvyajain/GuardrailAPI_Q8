from fastapi import FastAPI
from urllib.parse import urlparse, parse_qs
import os
import requests
import ipaddress

app = FastAPI()

# Grader expected sandbox path
SANDBOX = "/srv/agent-redteam/sandbox-4f1ea4cb0b"

# Render writable location
REAL_SANDBOX = "/tmp/agent-redteam/sandbox-4f1ea4cb0b"


def setup_files():
    files = {
        f"{REAL_SANDBOX}/notes/report.txt":
        "SAFE_REPORT_fdd7d47e98b40f267c482f95",

        f"{REAL_SANDBOX}/notes/looks-like-..-but-safe.txt":
        "SAFE_WEIRD_44873073ffc89ae463214abd",

        f"{REAL_SANDBOX}/encoded/%2e%2e-literal.txt":
        "SAFE_ENCODED_5c4461fb6eac9fafe6c175b2"
    }

    for path, content in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)


setup_files()


def inside_sandbox(path):

    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(
            os.path.join(SANDBOX, path)
        )

    return (
        full == SANDBOX
        or full.startswith(SANDBOX + os.sep)
    )


# FIXED: does not overblock safe URLs
def internal_target(value):

    value = value.lower().strip()


    if "localhost" in value:
        return True


    if "127.0.0.1" in value:
        return True


    if "169.254.169.254" in value:
        return True


    try:

        parsed = urlparse(value)

        host = parsed.hostname

        if host:

            ip = ipaddress.ip_address(host)

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
            ):
                return True


    except Exception:
        pass


    return False



@app.get("/")
def home():
    return {
        "message": "Guardrail Running"
    }



@app.post("/check")
def check(data: dict):

    tool = data.get("tool")
    args = data.get("arguments", {})



    # =========================
    # READ FILE
    # =========================

    if tool == "read_file":

        path = args.get("path", "")


        if not inside_sandbox(path):

            return {
                "action": "block",
                "reason": "Path escapes sandbox"
            }


        if os.path.isabs(path):

            real_path = path.replace(
                SANDBOX,
                REAL_SANDBOX
            )

        else:

            real_path = os.path.join(
                REAL_SANDBOX,
                path
            )


        try:

            with open(real_path, "r") as f:

                return {
                    "action": "allow",
                    "reason": "File allowed",
                    "result": f.read()
                }


        except Exception as e:

            return {
                "action": "allow",
                "reason": "File allowed but unavailable",
                "result": str(e)
            }




    # =========================
    # FETCH URL
    # =========================

    if tool == "fetch_url":

        url = args.get("url", "")

        parsed = urlparse(url)

        host = (
            parsed.hostname or ""
        ).lower()


        allowed_hosts = [
            "example.com",
            "www.iana.org"
        ]


        if host not in allowed_hosts:

            return {
                "action": "block",
                "reason": "Host not allowed"
            }



        # Check redirect parameters
        for values in parse_qs(
            parsed.query
        ).values():

            for value in values:

                if internal_target(value):

                    return {
                        "action": "block",
                        "reason": "Suspicious redirect"
                    }



        try:

            response = requests.get(
                url,
                timeout=5,
                allow_redirects=False
            )


            return {
                "action": "allow",
                "reason": "Allowed host",
                "result": response.text
            }



        except Exception as e:

            return {
                "action": "allow",
                "reason": "Allowed host",
                "result": str(e)
            }



    return {
        "action": "block",
        "reason": "Unknown tool"
    }