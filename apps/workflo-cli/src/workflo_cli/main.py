"""Main CLI entrypoint — `workflo run`, `workflo verify`, `workflo keygen`.

Uses Click for the command framework. The CLI is intentionally thin —
it builds a SandboxSpec, calls SandboxExecutor.run(), and prints the result.
All the heavy lifting is in the executor + probe engine.

Flag design:
  --test            Surface: repo's native pytest + basic smoke
  --deep-test       Deep: + LLM-generated edge cases, API contracts
  --aggressive-test Aggressive: + fuzz, property-based, chaos
  --security        Security: tenant isolation, network isolation, canary

  These are COMPOSABLE — combine any functional tier with --security.
  Only one functional tier may be selected at a time.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

import click

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tenant_shield_schema.sandbox import SandboxSpec

from quarantyne_executor import SandboxExecutor
from quarantyne_executor.executor import generate_sandbox_id
from sandbox_isolation import generate_keypair, verify_receipt_signature

# Hard limits to prevent DoS / abuse
MAX_RECEIPT_BYTES = 10 * 1024 * 1024   # 10 MB
MAX_OUTPUT_BYTES = 100 * 1024 * 1024   # 100 MB
MAX_CONFIG_BYTES = 1024 * 1024          # 1 MB
MAX_REPO_URL_LEN = 2048
MAX_COMMIT_SHA_LEN = 64

# Config file recognized keys (CLI flag names, not Python identifiers)
_CONFIG_KEYS = {
    "repo", "test", "deep_test", "aggressive_test", "security", "web",
    "start_command", "port", "commit_sha", "output", "worker_image",
    "deep_worker_image", "web_worker_image", "timeout", "memory", "cpu",
    "pubkey", "force", "dry_run", "via_api", "api_key",
}

# Repo URL must look like an http(s), git, or ssh URL.
# `file://` is ALSO allowed for local fixture testing in development — there's
# no risk of leaking customer code via file:// (the URL can only point at the
# host's filesystem, and the executor still clones into a tmpfs that gets
# unmounted post-run), and it lets us validate integration against local
# test repos without standing up a git HTTP server.
_REPO_URL_RE = re.compile(r"^(https?://|git@|git://|ssh://|file://).+", re.IGNORECASE)
# Commit SHA must be hex (allow full SHA, short SHA, or branch-like refs).
_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{1,64}$|^[A-Za-z0-9._/\-]{1,200}$")


def _validate_repo_url(url: str) -> str:
    """Strip and validate repo URL. Raises click.BadParameter on invalid input."""
    url = url.strip()
    if not url:
        raise click.BadParameter("Repo URL must not be empty")
    if len(url) > MAX_REPO_URL_LEN:
        raise click.BadParameter(f"Repo URL too long ({len(url)} > {MAX_REPO_URL_LEN})")
    if not _REPO_URL_RE.match(url):
        raise click.BadParameter(
            "Repo URL must start with https://, http://, git@, git://, or ssh://"
        )
    return url


def _validate_commit_sha(sha: Optional[str]) -> Optional[str]:
    """Validate commit SHA / ref format."""
    if sha is None:
        return None
    sha = sha.strip()
    if not sha:
        return None
    if len(sha) > MAX_COMMIT_SHA_LEN:
        raise click.BadParameter(f"Commit SHA too long ({len(sha)} > {MAX_COMMIT_SHA_LEN})")
    if not _COMMIT_SHA_RE.match(sha):
        raise click.BadParameter(
            f"Invalid commit SHA format: {sha!r}. "
            "Use hex chars or a valid ref name."
        )
    return sha


def _load_config_file(path: str) -> dict[str, Any]:
    """Load a YAML or JSON config file and validate its keys.

    Recognized keys match CLI flag names (with underscores instead of hyphens).
    Unknown keys raise an error to catch typos early.
    """
    config_path = Path(path).resolve()
    if not config_path.exists():
        raise click.BadParameter(f"Config file not found: {config_path}")

    try:
        raw = _safe_read_text(config_path, MAX_CONFIG_BYTES)
    except (OSError, UnicodeDecodeError) as e:
        raise click.BadParameter(f"Cannot read config file: {e}")

    ext = config_path.suffix.lower()
    if ext in (".yaml", ".yml"):
        if yaml is None:
            raise click.BadParameter(
                "YAML config requires PyYAML. Install with: pip install pyyaml"
            )
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise click.BadParameter(f"Invalid YAML in config: {e}")
    elif ext == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise click.BadParameter(f"Invalid JSON in config: {e}")
    else:
        raise click.BadParameter(
            f"Config file must be .yaml, .yml, or .json (got {ext!r})"
        )

    if not isinstance(data, dict):
        raise click.BadParameter(
            f"Config root must be a mapping/object, got {type(data).__name__}"
        )

    # Normalize keys: hyphens → underscores so `deep-test` and `deep_test` both work
    normalized: dict[str, Any] = {}
    for key, value in data.items():
        norm_key = key.replace("-", "_")
        if norm_key not in _CONFIG_KEYS:
            raise click.BadParameter(
                f"Unknown config key: {key!r}. "
                f"Recognized: {sorted(_CONFIG_KEYS)}"
            )
        normalized[norm_key] = value

    return normalized


def _safe_read_text(path: Path, max_bytes: int) -> str:
    """Read a text file with a hard size limit. Raises on overflow."""
    size = path.stat().st_size
    if size > max_bytes:
        raise click.BadParameter(
            f"File too large: {size} bytes (max {max_bytes})"
        )
    return path.read_text(encoding="utf-8")


def _load_ed25519_pubkey(path: Path) -> Ed25519PublicKey:
    """Load and validate an Ed25519 public key from PEM file.

    Raises click.BadParameter on any failure with a clear message.
    Does NOT trust a key that's the wrong type.
    """
    try:
        data = _safe_read_text(path, 4096)
    except (OSError, UnicodeDecodeError) as e:
        raise click.BadParameter(f"Cannot read pubkey file: {e}")

    try:
        key = serialization.load_pem_public_key(data.encode("utf-8"))
    except ValueError as e:
        raise click.BadParameter(f"Invalid PEM format: {e}")

    if not isinstance(key, Ed25519PublicKey):
        raise click.BadParameter(
            f"Pubkey must be Ed25519, got {type(key).__name__}. "
            f"workflo uses Ed25519 signatures exclusively."
        )

    return key


def _confirm_overwrite(path: Path) -> None:
    """Confirm before overwriting an existing file."""
    if path.exists():
        if not click.confirm(
            f"File {path} already exists. Overwrite?", default=False
        ):
            raise click.Abort()


def _internal_to_public_probe_groups(internal: list[str]) -> list[str]:
    """Translate CLI/internal probe-group names to the public contract names.

    The CLI internally uses the executor's vocabulary (surface, deep,
    aggressive, security, web); the frozen REST contract speaks the public
    vocabulary (test, deep-test, aggressive-test, security, web). The
    control-plane translates public -> internal server-side, so the CLI
    must send public names.
    """
    return [
        {
            "surface": "test",
            "deep": "deep-test",
            "aggressive": "aggressive-test",
        }.get(g, g)
        for g in internal
    ]


def _read_cli_workflo_yaml(repo_url: str) -> tuple[Optional[str], Optional[int]]:
    """Best-effort read of the target repo's workflo.yaml `web:` section.

    Only works for `file://` repos — for remote URLs the yaml is read
    INSIDE the container after the clone (worker-side resolve_web_config).
    This gives the CLI a local pre-flight fail-fast for dev/test repos
    while remote runs still get a clean worker-side failure.

    Returns (start_command, port), either may be None when absent.
    """
    if not repo_url.lower().startswith("file://"):
        return None, None
    repo_dir = Path(repo_url[len("file://"):])
    for name in ("workflo.yaml", "workflo.yml"):
        path = repo_dir / name
        if not path.is_file():
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and isinstance(data.get("web"), dict):
            web = data["web"]
            return web.get("start_command"), web.get("port")
    return None, None


@click.group()
@click.version_option(version="0.1.0", prog_name="workflo")
def cli():
    """workflo - sandboxed code-testing agent that verifies specific claims.

    Commands:
      run      Execute sandboxed tests against a repo
      verify   Verify a receipt's Ed25519 signature (Claim #4)
      keygen   Generate Ed25519 keypair for receipt signing
    """


@cli.command()
@click.option("--repo", default=None, help="Git repository URL to test")
@click.option("--test", "surface", is_flag=True, default=None, help="Surface tests: native pytest + basic smoke")
@click.option("--deep-test", "deep", is_flag=True, default=None, help="Deep tests: + generated edge cases, API contracts")
@click.option("--aggressive-test", "aggressive", is_flag=True, default=None, help="Aggressive tests: + fuzz, property-based, chaos")
@click.option("--security", is_flag=True, default=None, help="Security: tenant isolation, network isolation, canary")
@click.option("--web", is_flag=True, default=None, help="Web tier: run Playwright browser probes against a running app")
@click.option("--start-command", default=None,
              help="Command that starts the app under test (web tier). Shell-free; auto-start + port-wait.")
@click.option("--port", default=None, type=int,
              help="Port the app under test binds (web tier). Waited-on before browser probes run.")
@click.option("--commit-sha", default=None, help="Pin a specific commit (default: HEAD)")
@click.option("--output", "-o", default=None, help="Write the result JSON to a file")
@click.option(
    "--worker-image", default=None,
    help="Docker image for the sandbox worker (default: workflo-worker:latest)",
)
@click.option(
    "--deep-worker-image", default=None,
    help=(
        "Docker image for the model-bearing worker used by --deep-test / --aggressive-test. "
        "Auto-selected when those flags are set; --worker-image is for plain --test/--security. "
        "(default: workflo-worker-deep:latest)"
    ),
)
@click.option(
    "--web-worker-image", default=None,
    help=(
        "Docker image for the Playwright-bearing worker used by --web. "
        "Auto-selected when --web is set. (default: workflo-worker-web:latest)"
    ),
)
@click.option("--timeout", default=None, type=int, help="Sandbox timeout in seconds (default: 600)")
@click.option("--memory", default=None, type=int, help="Memory limit in MB (default: 2048)")
@click.option("--cpu", default=None, type=float, help="CPU core limit (default: 2.0)")
@click.option("--pubkey", default=None, help="Path to public key PEM for receipt verification")
@click.option("--force", is_flag=True, default=False, help="Overwrite output file if it exists")
@click.option("--via-api", "via_api", default=None,
              help="Base URL of a control-plane API (e.g. http://localhost:8000). "
                   "Round-trips through the frozen REST contract instead of running locally.")
@click.option("--api-key", default=None,
              help="API key for --via-api (X-API-Key header). If omitted, requests a demo token.")
@click.option("--dry-run", "--plan-only", "dry_run", is_flag=True, default=False,
              help="Validate and print what would run, then exit 0 — no Docker, no clone")
@click.option("--config", "config_path", default=None,
              help="Load defaults from a YAML or JSON config file (CLI flags override)")
def run(
    repo, surface, deep, aggressive, security, web, start_command, port,
    commit_sha, output, worker_image, deep_worker_image, web_worker_image,
    timeout, memory, cpu, pubkey, force, dry_run, config_path, via_api, api_key,
):
    """Run the sandbox pipeline against a repo.

    Probe groups are COMPOSABLE - combine any:
      --test            Surface: repo's pytest + basic smoke
      --deep-test       Deep: + generated edge cases, API contracts
      --aggressive-test Aggressive: + fuzz, property-based, chaos
      --security        Security: tenant isolation, network canary, teardown proof
      --web             Web: Playwright browser probes (needs --start-command/--port)

    Only one functional tier (--test / --deep-test / --aggressive-test) may
    be selected. --security is independent and composable.

    --deep-test / --aggressive-test auto-select the model-bearing worker image
    (`workflo-worker-deep:latest` by default) so the base image stays small
    and fast. Override with --deep-worker-image.

    --web auto-selects the Playwright-bearing worker image
    (`workflo-worker-web:latest` by default). Override with --web-worker-image.

    --dry-run validates everything and prints the plan without touching Docker.
    --config loads defaults from a file; explicit CLI flags override file values.

    Examples:
      workflo run --repo https://github.com/psf/requests.git --test
      workflo run --repo https://github.com/psf/requests.git --test --security
      workflo run --repo https://github.com/psf/requests.git --deep-test
      workflo run --repo https://github.com/psf/requests.git --web \
          --start-command "python app.py" --port 5000
      workflo run --config workflo.yaml --dry-run
      workflo run --config workflo.yaml --test --force
    """

    # --- 1. Load config file (if specified), then overlay CLI flags ---
    cfg: dict[str, Any] = {}
    if config_path:
        cfg = _load_config_file(config_path)

    # Helper: CLI flag wins over config file, config wins over built-in default
    def merge(cli_val: Any, cfg_key: str, default: Any = None) -> Any:
        if cli_val is not None:
            return cli_val
        if cfg_key in cfg:
            return cfg[cfg_key]
        return default

    repo = merge(repo, "repo")
    surface = merge(surface, "test", False)
    deep = merge(deep, "deep_test", False)
    aggressive = merge(aggressive, "aggressive_test", False)
    security = merge(security, "security", False)
    web = merge(web, "web", False)
    start_command = merge(start_command, "start_command")
    port = merge(port, "port")
    commit_sha = merge(commit_sha, "commit_sha")
    output = merge(output, "output")
    worker_image = merge(worker_image, "worker_image", "workflo-worker:latest")
    # The deep image has NO default here: we leave it None so the executor
    # can resolve to DEFAULT_DEEP_WORKER_IMAGE only when a deep-tier run is
    # actually requested. We surface it in the plan either way (resolved or
    # default) so a reviewer can see what image a deep-test run would use.
    deep_worker_image = merge(deep_worker_image, "deep_worker_image", None)
    web_worker_image = merge(web_worker_image, "web_worker_image", None)
    timeout = merge(timeout, "timeout", 600)
    memory = merge(memory, "memory", 2048)
    cpu = merge(cpu, "cpu", 2.0)
    force = merge(force, "force", False)
    via_api = merge(via_api, "via_api")
    api_key = merge(api_key, "api_key")

    # --- 2. Validate inputs FIRST - fail fast before any expensive work ---
    if not repo:
        raise click.BadParameter("--repo is required (or provide it in a config file)")
    repo = _validate_repo_url(repo)
    commit_sha = _validate_commit_sha(commit_sha)

    # Validate worker-image name (defense in depth)
    if not re.match(r"^[A-Za-z0-9._:/\-@]+$", worker_image):
        raise click.BadParameter(
            f"Invalid worker-image: {worker_image!r}. "
            "Only alphanumeric, '.', '_', ':', '/', '-', '@' allowed."
        )

    # Same validation for --deep-worker-image (if provided). An invalid deep
    # image name is a config bug; the CLI must fail fast rather than let the
    # docker create call reject it later inside the sandbox run (where the
    # failure surface is messier).
    if deep_worker_image is not None:
        if not re.match(r"^[A-Za-z0-9._:/\-@]+$", deep_worker_image):
            raise click.BadParameter(
                f"Invalid deep-worker-image: {deep_worker_image!r}. "
                "Only alphanumeric, '.', '_', ':', '/', '-', '@' allowed."
            )

    # Same validation for --web-worker-image (if provided).
    if web_worker_image is not None:
        if not re.match(r"^[A-Za-z0-9._:/\-@]+$", web_worker_image):
            raise click.BadParameter(
                f"Invalid web-worker-image: {web_worker_image!r}. "
                "Only alphanumeric, '.', '_', ':', '/', '-', '@' allowed."
            )

    # Validate ranges explicitly for clearer errors than Pydantic's defaults
    try:
        timeout = int(timeout)
        memory = int(memory)
        cpu = float(cpu)
    except (ValueError, TypeError) as e:
        raise click.BadParameter(f"Invalid numeric argument: {e}")

    if not (10 <= timeout <= 3600):
        raise click.BadParameter("timeout must be 10..3600 seconds")
    if not (256 <= memory <= 16384):
        raise click.BadParameter("memory must be 256..16384 MB")
    if not (0.5 <= cpu <= 8.0):
        raise click.BadParameter("cpu must be 0.5..8.0 cores")

    # --- 3. Build probe groups from flags ---
    probe_groups = []
    functional_tiers = []

    if surface:
        functional_tiers.append("surface")
    if deep:
        functional_tiers.append("deep")
    if aggressive:
        functional_tiers.append("aggressive")

    if len(functional_tiers) > 1:
        raise click.UsageError(
            "Only one functional tier allowed: choose one of --test, --deep-test, --aggressive-test"
        )
    if not functional_tiers and not security and not web:
        raise click.UsageError(
            "At least one probe group required: --test, --deep-test, --aggressive-test, --security, or --web"
        )

    # Fail fast for the web tier: a web run WITHOUT app-start config would
    # burn a full sandbox cycle just to report "start_command missing" from
    # inside the container. Validate the config HERE, pre-Docker, and also
    # resolve it from the target repo's workflo.yaml if the flags are absent.
    if web and not (start_command and port):
        yaml_start, yaml_port = _read_cli_workflo_yaml(repo)
        start_command = start_command or yaml_start
        port = port or yaml_port

    if web:
        missing = []
        if not start_command:
            missing.append("start_command")
        if not port:
            missing.append("port")
        if missing:
            flag_names = ", ".join("--" + m.replace("_", "-") for m in missing)
            raise click.UsageError(
                f"--web requires {flag_names}: "
                f"provide them on the command line, in the config file, or via the "
                f"repo's workflo.yaml:\n"
                f"  web:\n"
                f"    start_command: <cmd>\n"
                f"    port: <n>"
            )
        try:
            port = int(port)
        except (ValueError, TypeError):
            raise click.BadParameter(f"web port is not an integer: {port!r}")
        if not (1 <= port <= 65535):
            raise click.BadParameter(f"web port out of range: {port}")

    probe_groups.extend(functional_tiers)
    if security:
        probe_groups.append("security")
    if web:
        probe_groups.append("web")

    # --- 4. Validate output path safety ---
    output_path: Optional[Path] = None
    if output:
        output_path = Path(output).resolve()
        if not force:
            _confirm_overwrite(output_path)

    sandbox_id = generate_sandbox_id()

    # Web-tier config flows to the container via env vars (the executor
    # forwards spec.run_spec["env"] into the container env verbatim). The
    # worker's resolve_web_config reads these; workflo.yaml in the repo is
    # only a fallback for config NOT passed at the CLI.
    run_env: dict[str, str] = {}
    if web:
        run_env["WORKFLO_START_COMMAND"] = str(start_command)
        run_env["WORKFLO_WEB_PORT"] = str(port)

    run_spec = {
        "goal": "security" if security else "functional",
        # NOTE: `markers` here are workflo's internal probe tiers (surface/deep/etc.)
        # and are NOT passed through to pytest -m. Passing them as pytest markers
        # would deselect any test that doesn't bear an explicit `@pytest.mark.surface`
        # decorator — which is every test in a typical repo. The worker engine
        # treats `markers` as the probe-group identification only; pytest runs
        # the repo's whole suite unfiltered for surface tests.
        "markers": probe_groups,
        "probe_groups": probe_groups,
        "env": run_env,
    }

    try:
        spec = SandboxSpec(
            sandbox_id=sandbox_id,
            repo_url=repo,
            commit_sha=commit_sha,
            run_spec=run_spec,
            timeout_seconds=timeout,
            memory_mb=memory,
            cpu_cores=cpu,
        )
    except Exception as e:
        raise click.BadParameter(f"Invalid spec: {e}")

    # Resolve which worker image this run will use. The executor is the
    # source of truth at run time (see SandboxExecutor.select_worker_image),
    # but the CLI also needs the answer for the dry-run plan and for the
    # stderr banner — we mirror the same rule here so the printed plan
    # matches what the executor would actually do.
    from quarantyne_executor.executor import (
        DEFAULT_DEEP_WORKER_IMAGE,
        DEFAULT_WEB_WORKER_IMAGE,
        _DEEP_PROBE_GROUPS,
        _WEB_PROBE_GROUPS,
    )
    needs_deep_image = bool(set(probe_groups) & _DEEP_PROBE_GROUPS)
    needs_web_image = bool(set(probe_groups) & _WEB_PROBE_GROUPS)
    if needs_deep_image and needs_web_image:
        raise click.UsageError(
            "Combining a deep tier (--deep-test/--aggressive-test) with --web "
            "is not supported yet: the combined worker image "
            "(workflo-worker-deep-web:latest) has not been built. "
            "Choose one tier for this run."
        )
    if needs_deep_image:
        selected_worker_image = deep_worker_image or DEFAULT_DEEP_WORKER_IMAGE
    elif needs_web_image:
        selected_worker_image = web_worker_image or DEFAULT_WEB_WORKER_IMAGE
    else:
        selected_worker_image = worker_image

    # --- 5. Dry-run: print the plan and exit 0 (no Docker, no clone) ---
    if dry_run:
        plan = {
            "mode": "dry-run",
            "sandbox_id": sandbox_id,
            "repo": repo,
            "commit_sha": commit_sha,
            "probe_groups": probe_groups,
            # Surface BOTH images and the auto-switch decision so a reviewer
            # can see what was configured AND what was selected. The selected
            # image is the one that would actually be passed to `docker create`.
            "worker_image": worker_image,
            "deep_worker_image": deep_worker_image,
            "web_worker_image": web_worker_image,
            # `selected_worker_image` is the resolved image for this run. For
            # --deep-test/--aggressive-test, this is the deep image (the model-
            # bearing one). For --web, this is the web image (the Playwright
            # one). For --test/--security, this is the surface image.
            "selected_worker_image": selected_worker_image,
            "web_config": {
                "start_command": start_command,
                "port": port,
            } if web else None,
            "timeout_seconds": timeout,
            "memory_mb": memory,
            "cpu_cores": cpu,
            "output": str(output_path) if output_path else None,
            "spec_valid": True,
        }
        click.echo(json.dumps(plan, indent=2, sort_keys=True))
        sys.exit(0)

    # --- 6. Via-API run: round-trip through the frozen REST contract ---
    if via_api:
        _run_via_api(
            via_api=via_api,
            api_key=api_key,
            repo=repo,
            probe_groups=probe_groups,
            commit_sha=commit_sha,
            start_command=start_command,
            port=port,
            timeout=timeout,
            memory=memory,
            cpu=cpu,
            output_path=output_path,
        )

    # --- 7. Real run ---
    signer = generate_keypair()

    click.echo(f"Sandbox ID: {sandbox_id}", err=True)
    click.echo(f"Repo: {repo}", err=True)
    if commit_sha:
        click.echo(f"Commit: {commit_sha}", err=True)
    click.echo(f"Probe groups: {', '.join(probe_groups)}", err=True)
    # The banner prints both images when a deep-tier run was requested, so a
    # reviewer watching stderr sees the auto-switch happen explicitly.
    click.echo(f"Worker image: {worker_image}", err=True)
    if needs_deep_image:
        click.echo(f"Deep worker image (selected): {selected_worker_image}", err=True)
    if needs_web_image:
        click.echo(f"Web worker image (selected): {selected_worker_image}", err=True)
        click.echo(
            f"Web config: start_command={start_command!r} port={port}",
            err=True,
        )
    click.echo(f"Public key fingerprint: {signer.public_key_fingerprint}", err=True)
    click.echo("Starting sandbox run...", err=True)

    # Pass ALL THREE images to the executor — it picks the right one based on
    # the spec's probe groups (the executor is the single source of truth at
    # run time, so the CLI's banner choice and the executor's choice can't
    # drift).
    executor = SandboxExecutor(
        worker_image=worker_image,
        deep_worker_image=deep_worker_image,
        web_worker_image=web_worker_image,
        signer=signer,
    )

    try:
        result = executor.run(spec)
    except KeyboardInterrupt:
        click.echo("Interrupted - sandbox may not be fully torn down.", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"Executor error: {type(e).__name__}: {e}", err=True)
        sys.exit(2)

    click.echo(f"Run complete: {'SUCCESS' if result.success else 'FAILURE'}", err=True)
    click.echo(f"  Tests: {result.report.passed}/{result.report.total} passed", err=True)
    click.echo(f"  Container removed: {result.receipt.teardown_proof.container_removed}", err=True)
    click.echo(f"  Filesystem removed: {result.receipt.teardown_proof.filesystem_removed}", err=True)
    click.echo(f"  Canary passed (egress blocked): {not result.receipt.canary_check.request_succeeded}", err=True)
    click.echo(f"  Receipt signature: {result.receipt.signature[:16] if result.receipt.signature else 'NONE'}...", err=True)

    output_json = result.to_json()

    if output_path:
        if len(output_json.encode("utf-8")) > MAX_OUTPUT_BYTES:
            click.echo(f"Output too large ({MAX_OUTPUT_BYTES} byte limit)", err=True)
            sys.exit(1)
        try:
            output_path.write_text(output_json, encoding="utf-8")
            click.echo(f"Report written to {output_path}", err=True)
        except OSError as e:
            click.echo(f"Failed to write report to {output_path}: {e}", err=True)
            sys.exit(1)
    else:
        click.echo(output_json)

    sys.exit(0 if result.success else 1)


def _run_via_api(
    via_api: str,
    api_key: Optional[str],
    repo: str,
    probe_groups: list[str],
    commit_sha: Optional[str],
    start_command: Optional[str],
    port: Optional[int],
    timeout: int,
    memory: int,
    cpu: float,
    output_path: Optional[Path],
) -> None:
    """Round-trip a run through the frozen REST contract (docs/api_contract.md).

    Flow:
      1. (no --api-key) POST /v1/auth/demo-token to obtain the demo key
      2. POST /v1/runs with a RunRequest (public probe-group names)
      3. Poll GET /v1/runs/{run_id} until terminal (completed | failed)
      4. Print the RunStatus (with receipt when completed) and exit.

    Status semantics follow the contract: completed means the sandbox ran
    (test outcomes are inside the receipt — failing tests are NOT an exit
    code 1), failed means infrastructure crashed (error field, no receipt,
    exit code 1).
    """
    import httpx
    import time

    base = via_api.rstrip("/")
    headers: dict[str, str] = {}

    if not api_key:
        click.echo(f"Requesting demo token from {base}...", err=True)
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.post(f"{base}/v1/auth/demo-token")
            if resp.status_code != 200:
                click.echo(
                    f"Failed to obtain demo token: HTTP {resp.status_code}: {resp.text[:200]}",
                    err=True,
                )
                sys.exit(2)
            api_key = resp.json()["api_key"]
        except httpx.HTTPError as e:
            click.echo(f"Cannot reach control plane at {base}: {e}", err=True)
            sys.exit(2)

    headers["X-API-Key"] = api_key

    request_body: dict[str, Any] = {
        "repo_url": repo,
        "probe_groups": _internal_to_public_probe_groups(probe_groups),
        "config": {
            "timeout_seconds": timeout,
            "memory_mb": memory,
            "cpu_cores": cpu,
        },
    }
    if commit_sha:
        request_body["commit_sha"] = commit_sha
    if start_command:
        request_body["start_command"] = start_command
    if port is not None:
        request_body["port"] = port

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(f"{base}/v1/runs", json=request_body, headers=headers)
            if resp.status_code != 200:
                detail = ""
                try:
                    detail = resp.json().get("detail", "")
                except ValueError:
                    detail = resp.text[:200]
                click.echo(
                    f"Run rejected: HTTP {resp.status_code}: {detail}",
                    err=True,
                )
                sys.exit(2)
            run = resp.json()
    except httpx.HTTPError as e:
        click.echo(f"Cannot submit run to {base}: {e}", err=True)
        sys.exit(2)

    run_id = run["run_id"]
    click.echo(f"Run submitted: {run_id} (status={run['status']})", err=True)

    # Poll until terminal. Polling interval grows: 0.5s -> 1s -> 2s,
    # capped, so short runs finish fast and long runs don't hammer the API.
    interval = 0.5
    while run["status"] in ("queued", "running"):
        time.sleep(interval)
        interval = min(interval * 2, 5.0)
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(f"{base}/v1/runs/{run_id}", headers=headers)
                if resp.status_code != 200:
                    click.echo(
                        f"Status poll failed: HTTP {resp.status_code}: {resp.text[:200]}",
                        err=True,
                    )
                    sys.exit(2)
                run = resp.json()
        except httpx.HTTPError as e:
            click.echo(f"Cannot poll run status at {base}: {e}", err=True)
            sys.exit(2)

    click.echo(f"Run finished: status={run['status']}", err=True)

    if run["status"] == "failed":
        click.echo(f"Run failed: {run.get('error')}", err=True)
        sys.exit(1)

    receipt = run.get("receipt")
    if receipt is None:
        click.echo("Run completed but no receipt present in the response.", err=True)
        sys.exit(2)

    output_json = json.dumps(receipt, indent=2, sort_keys=True)
    if output_path:
        if len(output_json.encode("utf-8")) > MAX_OUTPUT_BYTES:
            click.echo(f"Output too large ({MAX_OUTPUT_BYTES} byte limit)", err=True)
            sys.exit(1)
        try:
            output_path.write_text(output_json, encoding="utf-8")
            click.echo(f"Report written to {output_path}", err=True)
        except OSError as e:
            click.echo(f"Failed to write report to {output_path}: {e}", err=True)
            sys.exit(1)
    else:
        click.echo(output_json)

    # completed means the sandbox ran to completion — test failures live
    # inside the receipt and do NOT affect the exit code (the contract's
    # status semantics: status reflects infrastructure, not test outcomes).
    sys.exit(0)


@cli.command()
@click.option("--receipt", "receipt_path", required=True, help="Path to receipt JSON file")
@click.option("--pubkey", required=True, help="Path to Ed25519 public key PEM file")
@click.option("--fingerprint", default=None, help="Expected public key fingerprint (SHA-256 hex)")
def verify(receipt_path, pubkey, fingerprint):
    """Verify a receipt's Ed25519 signature against a published public key.

    Backs Claim #4: "every run produces a signed, tamper-evident receipt."
    This is the command an outside verifier runs to check that a receipt
    was actually signed by workflo and hasn't been tampered with.
    """

    # Read receipt with size limit to prevent DoS
    receipt_file = Path(receipt_path)
    try:
        receipt_text = _safe_read_text(receipt_file, MAX_RECEIPT_BYTES)
    except (OSError, UnicodeDecodeError) as e:
        click.echo(f"FAILED: cannot read receipt file: {e}", err=True)
        sys.exit(1)

    try:
        receipt_data = json.loads(receipt_text)
    except json.JSONDecodeError as e:
        click.echo(f"FAILED: receipt is not valid JSON: {e}", err=True)
        sys.exit(1)

    if not isinstance(receipt_data, dict):
        click.echo(f"FAILED: receipt root must be a JSON object, got {type(receipt_data).__name__}", err=True)
        sys.exit(1)

    receipt_dict = receipt_data.get("receipt", receipt_data)

    try:
        from tenant_shield_schema.sandbox import SignedReceipt
        receipt = SignedReceipt(**receipt_dict)
    except Exception as e:
        click.echo(f"FAILED: receipt does not match schema: {e}", err=True)
        sys.exit(1)

    # Load and validate Ed25519 pubkey
    pubkey_file = Path(pubkey)
    try:
        public_key = _load_ed25519_pubkey(pubkey_file)
    except click.BadParameter as e:
        click.echo(f"FAILED: {e.message}", err=True)
        sys.exit(1)

    # Optional fingerprint check
    if fingerprint:
        from sandbox_isolation import fingerprint_public_key
        actual_fp = fingerprint_public_key(public_key)
        if actual_fp != fingerprint:
            click.echo(
                f"FAILED: fingerprint mismatch (expected {fingerprint}, got {actual_fp})",
                err=True,
            )
            sys.exit(1)

    if verify_receipt_signature(receipt, public_key):
        click.echo("VERIFIED: receipt signature is valid.")
        click.echo(f"  Sandbox ID: {receipt.sandbox_id}", err=True)
        click.echo(f"  Fingerprint: {receipt.public_key_fingerprint}", err=True)
        sys.exit(0)
    else:
        click.echo("FAILED: receipt signature is INVALID or tampered.", err=True)
        sys.exit(1)


@cli.command()
@click.option("--output", "-o", default=None, help="Write the public key PEM to a file")
@click.option("--force", is_flag=True, help="Overwrite output file if it exists")
def keygen(output, force):
    """Generate a new Ed25519 keypair for receipt signing.

    Prints the public key PEM to stdout and the fingerprint to stderr.
    The private key is printed to stderr - capture it securely.
    """

    signer = generate_keypair()

    public_pem = signer.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    private_pem = signer.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    if output:
        output_path = Path(output).resolve()
        if not force and output_path.exists():
            if not click.confirm(
                f"File {output_path} already exists. Overwrite?", default=False
            ):
                raise click.Abort()
        try:
            output_path.write_text(public_pem, encoding="utf-8")
            click.echo(f"Public key written to {output_path}", err=True)
        except OSError as e:
            click.echo(f"Failed to write public key: {e}", err=True)
            sys.exit(1)
    else:
        click.echo(public_pem)

    click.echo(f"Fingerprint: {signer.public_key_fingerprint}", err=True)
    click.echo("Private key (keep secret!):", err=True)
    click.echo(private_pem, err=True)


if __name__ == "__main__":
    cli()