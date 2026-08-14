"""Sandbox lifecycle models — the contract for ephemeral, no-retention execution.

These models are the architectural enforcement of the Airlock privacy guarantee.
A SandboxSpec describes what to spin up; a SandboxReceipt proves what was spun
down. Nothing else survives a run by design — not source code, not prompts,
not logs of customer data — only these structured artifacts.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class SandboxSpec(BaseModel):
    """Input contract: what the Control Plane hands the Sandbox Executor."""

    sandbox_id: str = Field(description="Unique one-time ID for this sandbox run")
    repo_url: str = Field(description="Git URL to clone inside the sandbox")
    commit_sha: Optional[str] = Field(default=None, description="Pinned commit, if not HEAD")
    run_spec: dict = Field(
        description="The RunSpec dict passed through to the worker-engine payload"
    )
    # Hard limits — enforced by the executor, not configurable by the caller
    timeout_seconds: int = Field(default=600, ge=10, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=16384)
    cpu_cores: float = Field(default=2.0, ge=0.5, le=8.0)
    # Network: by default, egress is BLOCKED except back to the Control Plane status endpoint
    allowed_egress_hosts: list[str] = Field(
        default_factory=list,
        description="Hosts the sandbox may reach. Empty = no egress (default for privacy).",
    )


class SandboxLifecycleEvent(BaseModel):
    """One row in the sandbox's lifecycle log — emitted by the executor."""

    sandbox_id: str
    event: str  # "created" | "repo_cloned" | "tests_started" | "tests_completed" | "teardown_started" | "destroyed"
    timestamp: datetime
    detail: dict = Field(default_factory=dict)


class TeardownProof(BaseModel):
    """Evidence that the sandbox was actually destroyed, not just claimed to be."""

    sandbox_id: str
    container_id: Optional[str] = Field(default=None, description="Docker container ID at teardown")
    filesystem_wipe_method: str = Field(
        default="tmpfs_umount",
        description="How the filesystem was destroyed. tmpfs_umount = unmounted tmpfs volume.",
    )
    container_removed: bool = Field(
        default=False,
        description="True if docker rm -f succeeded and post-check confirms no container exists",
    )
    filesystem_removed: bool = Field(
        default=False,
        description="True if post-teardown check confirms tmpfs mount no longer exists",
    )
    no_snapshot_retained: bool = Field(
        default=True,
        description="True if no Docker commit/image snapshot was taken before destruction",
    )
    # Model inference teardown — the deep-test / aggressive-test stages
    # run a local LLM (Ollama + Qwen2.5-Coder) which writes state to
    # ~/.ollama. For surface / security runs, the model stage never runs.
    #
    # We use Optional[bool] with default=None so the verifier can distinguish
    # three states cleanly:
    #   None = not applicable (plain --test, no model stage ran)
    #   True = model stage ran AND state was wiped (clean)
    #   False = model stage ran AND state was NOT wiped (FAIL CLOSED)
    #
    # Collapsing "not applicable" into False would mean every non-deep-test
    # receipt looks like a teardown failure.
    model_inference_teardown: Optional[bool] = Field(
        default=None,
        description=(
            "None = model stage never ran (--test/--security only); "
            "True = model stage ran and Ollama state was wiped; "
            "False = model stage ran but state was NOT wiped."
        ),
    )
    model_inference_error: Optional[str] = Field(
        default=None,
        description="Human-readable error if model_inference_teardown is False or None.",
    )
    destroyed_at: datetime


class CanaryCheckResult(BaseModel):
    """Result of the Claim #3 canary — a real outbound request that MUST fail."""

    sandbox_id: str
    attempted_at: datetime
    target_host: str = Field(
        default="https://example.com",
        description="Host the sandbox was asked to reach. Default is a known-good external host.",
    )
    request_succeeded: bool = Field(
        description="True ONLY if the sandbox could reach the target. Expected False.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Connection error string if the request failed (expected case).",
    )


class RunReport(BaseModel):
    """The customer-facing result — test counts, not source code."""

    sandbox_id: str
    run_id: Optional[str] = None
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    duration_seconds: float = 0.0
    soc2_controls_covered: list[str] = Field(default_factory=list)
    findings: list[dict] = Field(
        default_factory=list,
        description="Structured findings — test name + status + assertion. Never source code.",
    )


class WebProbeResult(BaseModel):
    """Outcome of the Playwright-driven browser probes (the `web` tier).

    None on the receipt = web tier not requested (same discipline as
    `model_inference_teardown`). When the web tier IS requested, this is
    populated even if the app-under-test failed to start — a broken app is
    a valid, reportable outcome (probe failed), not a Workflo bug.
    """

    base_url: str = Field(description="URL the probes were run against (e.g. http://127.0.0.1:5000)")
    probes: list[dict] = Field(
        default_factory=list,
        description="Per-probe results: {name, passed, detail}. Never contains source code.",
    )
    app_start_error: Optional[str] = Field(
        default=None,
        description="If the app under test could not be started/bound, the error message. "
        "Probes list may be empty when this is set.",
    )


class SignedReceipt(BaseModel):
    """The tamper-evident receipt that closes every run. This is what survives."""

    sandbox_id: str
    issued_at: datetime
    run_report: RunReport
    teardown_proof: TeardownProof
    canary_check: CanaryCheckResult
    lifecycle_events: list[SandboxLifecycleEvent] = Field(default_factory=list)
    # Web probes — None when the web tier wasn't requested. Same three-state
    # discipline as model_inference_teardown: None = not applicable, never
    # conflated with "ran and everything failed".
    web_probes: Optional[WebProbeResult] = Field(
        default=None,
        description="None = web tier not requested. Populated (even with failing "
        "probes or an app-start error) when the web tier ran.",
    )
    # The signature is over a canonical JSON of all the above fields
    signature_algorithm: str = Field(default="ed25519")
    public_key_fingerprint: Optional[str] = Field(
        default=None,
        description="SHA-256 fingerprint of the public key the receipt can be verified against. "
        "Filled by ReceiptSigner.sign(); None until signed.",
    )
    signature: Optional[str] = Field(
        default=None,
        description="Hex-encoded Ed25519 signature over the canonical payload. "
        "Filled by ReceiptSigner.sign(); None until signed.",
    )

    def canonical_payload(self) -> str:
        """The exact bytes that were signed. Stable across runs."""
        import json

        payload = {
            "sandbox_id": self.sandbox_id,
            "issued_at": self.issued_at.isoformat(),
            "run_report": self.run_report.model_dump(mode="json"),
            "teardown_proof": self.teardown_proof.model_dump(mode="json"),
            "canary_check": self.canary_check.model_dump(mode="json"),
            "lifecycle_events": [e.model_dump(mode="json") for e in self.lifecycle_events],
            "web_probes": self.web_probes.model_dump(mode="json") if self.web_probes else None,
            "signature_algorithm": self.signature_algorithm,
            "public_key_fingerprint": self.public_key_fingerprint or "",
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
