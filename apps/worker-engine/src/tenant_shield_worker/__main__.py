"""Module entrypoint so `python -m tenant_shield_worker` works."""

from tenant_shield_worker.main import run_worker


if __name__ == "__main__":
    run_worker()
