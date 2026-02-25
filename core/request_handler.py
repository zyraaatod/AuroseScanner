import random
import time
from dataclasses import dataclass

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


@dataclass
class ResponseMeta:
    ok: bool
    status_code: int
    url: str
    headers: dict
    body: str
    elapsed: float
    error: str = ""


class RequestHandler:
    def __init__(self, timeout=10, retries=2, delay=0.25):
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.session = requests.Session()

    def request(self, method, url, **kwargs):
        method = (method or "GET").upper()
        headers = kwargs.pop("headers", {})
        merged_headers = {"User-Agent": self.random_ua(), **headers}
        kwargs["headers"] = merged_headers
        kwargs["timeout"] = kwargs.get("timeout", self.timeout)
        kwargs["verify"] = kwargs.get("verify", False)
        kwargs["allow_redirects"] = kwargs.get("allow_redirects", True)

        last_error = ""
        for attempt in range(self.retries):
            try:
                start = time.perf_counter()
                res = self.session.request(method, url, **kwargs)
                elapsed = time.perf_counter() - start
                return ResponseMeta(
                    ok=True,
                    status_code=res.status_code,
                    url=res.url,
                    headers=dict(res.headers),
                    body=res.text or "",
                    elapsed=elapsed,
                )
            except requests.RequestException as exc:
                last_error = str(exc)
                if attempt == self.retries - 1:
                    break
                time.sleep(self.delay * (attempt + 1))

        return ResponseMeta(
            ok=False,
            status_code=0,
            url=url,
            headers={},
            body="",
            elapsed=0.0,
            error=last_error,
        )

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def random_ua(self):
        ua = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/94.0",
        ]
        return random.choice(ua)
