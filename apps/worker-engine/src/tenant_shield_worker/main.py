"""Worker main loop — polls the queue for run specs and executes them."""

import json
import sys
from tenant_shield_utils.logging import configure_logging, get_logger

from tenant_shield_worker.executor import execute_run
from tenant_shield_worker.streamer import ResultStreamer

logger = get_logger(__name__)


def run_worker():
    """Main worker loop. Polls Redis for incoming run specs."""
    configure_logging()
    logger.info("worker.start", extra={"extra_data": {"mode": "queue"}})

    # TODO: connect to Redis, subscribe to "test-runs" queue
    # For now, accept a single spec via stdin for local testing
    if len(sys.argv) > 1:
        spec_path = sys.argv[1]
        with open(spec_path) as f:
            spec = json.load(f)
        _process(spec)
    else:
        logger.info("No spec provided. Running in idle mode (waiting for queue).")
        _idle_loop()


def _process(spec: dict):
    run_id = spec.get("run_id", "local")
    logger.info("run.received", extra={"extra_data": {"run_id": run_id, "goal": spec.get("goal")}})
    streamer = ResultStreamer(run_id=run_id)
    try:
        summary = execute_run(spec, streamer)
        streamer.complete(summary)
        logger.info("run.completed", extra={"extra_data": {"run_id": run_id, "summary": summary.model_dump()}})
    except Exception as e:
        logger.error("run.failed", extra={"extra_data": {"run_id": run_id, "error": str(e)}})
        streamer.fail(str(e))


def _idle_loop():
    import time
    while True:
        time.sleep(5)
        logger.info("worker.heartbeat")


if __name__ == "__main__":
    run_worker()
