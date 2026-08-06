"""Main CLI entry point for the Tenant Shield agent."""

import click
from rich.console import Console

from tenant_shield_agent.commands.auth import auth
from tenant_shield_agent.commands.test import test
from tenant_shield_agent.commands.runs import runs

console = Console()


@click.group()
@click.version_option(package_name="tenant-shield-agent")
def main():
    """Tenant Shield — multi-tenant isolation testing from your terminal."""
    pass


main.add_command(auth)
main.add_command(test)
main.add_command(runs)


if __name__ == "__main__":
    main()
