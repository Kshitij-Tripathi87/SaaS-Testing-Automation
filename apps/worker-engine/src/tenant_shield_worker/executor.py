"""Test executor — runs pytest with the spec's markers and collects results."""

import subprocess
import json
import tempfile
from pathlib import Path
from tenant_shield_schema import RunSpec, RunSummary
from tenant_shield_worker.streamer import ResultStreamer


def execute_run(spec_dict: dict, streamer: ResultStreamer) -> RunSummary:
    """Execute a test run based on the spec and return the summary."""
    spec = RunSpec(**spec_dict)

    markers = " ".join(spec.markers) if spec.markers else ""
    marker_arg = ["-m", markers] if markers else []

    results_path = Path(tempfile.mktemp(suffix=".json"))

    streamer.log(f"Executing pytest with markers: {markers or '(none)'}")

    cmd = ["pytest", "-v", "--json-report", f"--json-report-file={results_path}"]
    cmd.extend(marker_arg)

    if spec.targets.include:
        cmd.extend(spec.targets.include)
    if spec.targets.exclude:
        for excl in spec.targets.exclude:
            cmd.extend(["--deselect", excl])

    env_overrides = spec.env
    streamer.log(f"env overrides: {env_overrides}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=spec.config.timeout_seconds)
        streamer.log(proc.stdout)
        if proc.returncode != 0:
            streamer.log(f"[STDERR]\n{proc.stderr}")
    except FileNotFoundError:
        streamer.log("pytest not found in PATH")
    except subprocess.TimeoutExpired:
        streamer.log("Test run timed out")

    summary = _parse_results(results_path)
    return summary


def _parse_results(results_path: Path) -> RunSummary:
    """Parse the pytest-json-report file into a RunSummary."""
    if not results_path.exists():
        return RunSummary()

    with open(results_path) as f:
        data = json.load(f)

    summary_data = data.get("summary", {})
    return RunSummary(
        total=summary_data.get("total", 0),
        passed=summary_data.get("passed", 0),
        failed=summary_data.get("failed", 0),
        skipped=summary_data.get("skipped", 0),
        deselected=summary_data.get("deselected", 0),
        duration_seconds=data.get("duration", 0.0),
    )
