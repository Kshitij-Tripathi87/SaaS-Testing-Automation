import os
import json
import pytest
from playwright.sync_api import sync_playwright
from src.config.settings import EnvironmentConfig, BrowserStackConfig
from src.api.client import APIClient


@pytest.fixture(scope="session")
def env_config():
    return EnvironmentConfig.from_env()


@pytest.fixture(scope="session")
def browserstack_config():
    return BrowserStackConfig.from_env()


@pytest.fixture(scope="function")
def api_client(env_config):
    auth_token = os.getenv("API_AUTH_TOKEN")
    return APIClient(
        base_url=env_config.api_url,
        tenant_id=env_config.tenant_id,
        auth_token=auth_token,
    )


@pytest.fixture(scope="function")
def browser_context(env_config):
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=env_config.headless,
            args=["--disable-gpu"],
        )
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=True,
        )
        page = context.new_page()
        yield page
        context.close()
        browser.close()


@pytest.fixture(scope="function")
def browser_context_mobile(env_config):
    with sync_playwright() as p:
        iphone = p.devices["iPhone 14"]
        browser = p.chromium.launch(
            headless=env_config.headless,
            args=["--disable-gpu"],
        )
        context = browser.new_context(**iphone, ignore_https_errors=True)
        page = context.new_page()
        yield page
        context.close()
        browser.close()


@pytest.fixture(scope="function")
def browserstack_context(request, browserstack_config):
    if not browserstack_config.username or not browserstack_config.access_key:
        pytest.skip("BrowserStack credentials not configured")

    capabilities = {
        "browser": request.param.get("browser", "chrome"),
        "browser_version": "latest",
        "os": request.param.get("os", "Windows"),
        "os_version": request.param.get("os_version", "11"),
        "name": request.node.name,
        "build": browserstack_config.build_name,
        "browserstack.networkLogs": browserstack_config.network_logs,
        "browserstack.consoleLogs": browserstack_config.console_logs,
        "browserstack.video": browserstack_config.video,
    }

    ws_endpoint = (
        f"wss://cdp.browserstack.com/playwright"
        f"?caps={json.dumps(capabilities)}"
    )

    with sync_playwright() as p:
        browser = p.chromium.connect(ws_endpoint)
        page = browser.new_page()
        yield page
        browser.close()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    if report.when == "call" and report.failed:
        page = item.funcargs.get("browser_context")
        if page:
            test_name = item.nodeid.replace("::", "_").replace("/", "_")
            screenshot_dir = "reports/screenshots"
            os.makedirs(screenshot_dir, exist_ok=True)
            page.screenshot(path=f"{screenshot_dir}/{test_name}_fail.png")
