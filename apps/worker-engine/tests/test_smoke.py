from tenant_shield_worker.adapters.browser import BrowserAdapter
from tenant_shield_schema import BrowserMode


def test_browser_adapter_init():
    adapter = BrowserAdapter(mode=BrowserMode.CONTAINER)
    assert adapter.mode == BrowserMode.CONTAINER


def test_grid_adapter():
    from tenant_shield_worker.adapters.grid import GridAdapter
    grid = GridAdapter(provider="browserstack", username="user", access_key="key")
    endpoint = grid.build_endpoint()
    assert "browserstack" in endpoint
