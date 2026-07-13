# WorkFlow Pro - B2B SaaS Test Automation Suite

Automated testing framework for WorkFlow Pro, a multi-tenant B2B project management platform. Covers web (Chrome, Firefox, Safari), mobile (iOS, Android), API, and security testing.

## Project Structure

```
workflowpro-tests/
├── src/                    # Source code
│   ├── api/               # API client and auth management
│   ├── ui/pages/          # Page Object Model (Login, Dashboard, Projects)
│   ├── ui/components/     # Reusable UI components
│   ├── mobile/pages/      # Mobile-specific page objects
│   └── config/            # Environment and browser configuration
├── tests/                 # Test suites
│   ├── conftest.py        # Shared fixtures and hooks
│   ├── test_login.py      # Login flow tests
│   ├── test_multi_tenant.py# Multi-tenant access tests
│   ├── integration/       # API + UI integration tests
│   └── security/          # Tenant isolation security tests
├── data/                  # Test data
│   ├── factories/         # Data factory classes
│   └── fixtures/          # YAML test data files
├── reports/               # Test reports and screenshots (gitignored)
├── pytest.ini             # Pytest configuration
└── requirements.txt       # Python dependencies
```

## Setup

### Prerequisites

- Python 3.10+
- Playwright browsers
- Access to WorkFlow Pro staging environment
- BrowserStack account (optional, for cross-platform testing)

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd workflowpro-tests

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
# For full browser support: playwright install
```

### Environment Variables

Copy `.env.example` and configure:

```bash
# Required
TEST_ENV=staging
BASE_URL=https://company1.staging.workflowpro.com
API_BASE_URL=https://api.staging.workflowpro.com
TENANT_ID=company1
TEST_EMAIL=admin@company1.com
TEST_PASSWORD=<password>
API_AUTH_TOKEN=<token>

# Tenant-specific (for isolation tests)
COMPANY1_TOKEN=<token>
COMPANY2_TOKEN=<token>

# Optional: 2FA testing
TEST_2FA_CODE=123456

# Optional: BrowserStack
BROWSERSTACK_USERNAME=<username>
BROWSERSTACK_ACCESS_KEY=<key>
BROWSERSTACK=true
```

## Running Tests

```bash
# All tests
pytest

# By marker
pytest -m smoke
pytest -m integration
pytest -m security
pytest -m mobile

# Parallel execution (4 workers)
pytest -n 4

# With rerun for flaky tests
pytest --reruns 2

# Specific test file
pytest tests/test_login.py
pytest tests/integration/test_project_lifecycle.py

# With Allure reporting
pytest --alluredir=reports/allure-results
allure serve reports/allure-results

# Cross-browser via BrowserStack
BROWSERSTACK=true pytest -m integration -n 2
```

## Test Strategy

### Layers Tested

| Layer | Tool | Approach |
|---|---|---|
| API | pytest + requests | Direct endpoint testing with retry logic |
| Web UI | Playwright (Page Object Model) | User flow simulation with auto-waiting |
| Mobile Web | Playwright (device emulation) + BrowserStack | Responsive design verification |
| Security | pytest + API client | Cross-tenant access control validation |

### Key Design Decisions

1. **Page Object Model**: UI interaction logic is separated from test assertions. When the UI changes, only the page object needs updating.

2. **Factory Pattern**: Test data is generated uniquely per run (UUID-based names) to enable safe parallel execution and avoid test data collisions.

3. **Auto-Retrying Assertions**: Playwright's `expect()` replaces raw `is_visible()` calls to eliminate race conditions.

4. **Fixture-Based Cleanup**: `yield` fixtures guarantee browser/API teardown even on assertion failures, preventing resource leaks in CI.

5. **Tenant Isolation**: Security tests use separate API clients per tenant to programmatically verify data boundaries.

### Flaky Test Prevention

- Replace static waits with Playwright's auto-waiting (`expect`, `wait_for`)
- Use `networkidle` load state for SPA navigation
- Set explicit viewport to avoid responsive layout changes
- Capture screenshots on failure for debugging
- Retry flaky operations with exponential backoff
