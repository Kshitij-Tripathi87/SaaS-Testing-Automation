import os
import json
import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from requests.exceptions import ConnectionError, Timeout, HTTPError


class APIClient:
    def __init__(self, base_url=None, tenant_id=None, auth_token=None):
        self.base_url = base_url or os.getenv("API_BASE_URL", "https://api.workflowpro.com")
        self.tenant_id = tenant_id or os.getenv("TENANT_ID", "company1")
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Tenant-ID": self.tenant_id,
        })
        if auth_token:
            self.session.headers["Authorization"] = f"Bearer {auth_token}"

    def set_auth_token(self, token):
        self.session.headers["Authorization"] = f"Bearer {token}"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((ConnectionError, Timeout, HTTPError)),
        reraise=True,
    )
    def request(self, method, path, **kwargs):
        url = f"{self.base_url}{path}"
        response = self.session.request(method, url, **kwargs)
        if response.status_code >= 500:
            response.raise_for_status()
        return response

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)

    def put(self, path, **kwargs):
        return self.request("PUT", path, **kwargs)

    def delete(self, path, **kwargs):
        return self.request("DELETE", path, **kwargs)
