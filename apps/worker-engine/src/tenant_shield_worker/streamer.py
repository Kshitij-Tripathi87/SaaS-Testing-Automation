"""Result streamer — sends logs and results to the Control Plane."""

import httpx
from typing import Optional
from tenant_shield_schema import RunSummary
from tenant_shield_utils.config import get_config_value


class ResultStreamer:
    """Streams test logs and final results back to the Control Plane API."""

    def __init__(self, run_id: str, control_plane_url: Optional[str] = None, api_key: Optional[str] = None):
        self.run_id = run_id
        self.control_plane_url = control_plane_url or get_config_value("defaults.api_base_url", "http://localhost:8000")
        self.api_key = api_key or get_config_value("auth.api_key", "")
        self._log_buffer: list[str] = []

    @property
    def _headers(self) -> dict:
        return {"X-TenantShield-Key": self.api_key}

    def log(self, line: str) -> None:
        """Send a log line to the Control Plane."""
        self._log_buffer.append(line)
        try:
            with httpx.Client(headers=self._headers, timeout=10) as client:
                client.post(
                    f"{self.control_plane_url}/v1/runs/{self.run_id}/logs",
                    params={"log_line": line},
                )
        except Exception:
            pass

    def complete(self, summary: RunSummary) -> None:
        """Signal run completion with the final summary."""
        try:
            with httpx.Client(headers=self._headers, timeout=30) as client:
                client.post(
                    f"{self.control_plane_url}/v1/runs/{self.run_id}/complete",
                    json=summary.model_dump(),
                )
        except Exception:
            pass

    def fail(self, error: str) -> None:
        """Signal run failure."""
        try:
            with httpx.Client(headers=self._headers, timeout=30) as client:
                client.post(
                    f"{self.control_plane_url}/v1/runs/{self.run_id}/complete",
                    json={"status": "failed", "error": error},
                )
        except Exception:
            pass
