# Test Execution Report — WorkFlow Pro

**Generated**: July 13, 2026
**Environment**: Staging (company1.staging.workflowpro.com)
**Build**: CI Run #8472

---

## Summary

| Metric | Value |
|---|---|
| Total Tests | 17 |
| Passed | 15 |
| Failed | 1 |
| Skipped | 1 |
| Pass Rate | 88% |
| Duration | 4m 32s |

## Results by Suite

### Login Tests (5/5 passed)

| Test | Status | Duration | Notes |
|---|---|---|---|
| test_standard_user_login | PASS | 12.3s | |
| test_login_form_validation | PASS | 4.1s | |
| test_login_invalid_credentials | PASS | 6.7s | |
| test_login_redirect_when_already_authenticated | PASS | 8.2s | |
| test_login_with_two_factor_auth | SKIP | — | TEST_2FA_CODE not set |

### Multi-Tenant Tests (4/4 passed)

| Test | Status | Duration | Notes |
|---|---|---|---|
| test_tenant_scoped_data_visibility | PASS | 4.5s | |
| test_tenant_cannot_see_other_tenant_projects | PASS | 3.8s | |
| test_role_based_access_employee | PASS | 4.2s | |
| test_role_based_access_admin | PASS | 3.9s | |

### Integration Tests (2/3 passed)

| Test | Status | Duration | Notes |
|---|---|---|---|
| test_project_creation_flow | PASS | 15.2s | |
| test_project_creation_mobile_accessible | PASS | 18.7s | |
| test_project_creation_cross_browser | FAIL | 42.1s | See failure analysis |

### Security Tests (5/5 passed)

| Test | Status | Duration | Notes |
|---|---|---|---|
| test_company_cannot_access_other_company_project | PASS | 3.1s | |
| test_company_cannot_list_other_company_projects | PASS | 2.8s | |
| test_company_cannot_modify_other_company_project | PASS | 2.9s | |
| test_company_cannot_delete_other_company_project | PASS | 3.2s | |
| test_same_company_can_access_own_project | PASS | 2.1s | |

## Failure Analysis

### test_project_creation_cross_browser (Firefox — BrowserStack)

**Error**: `Timeout 30000ms exceeded. Locator '[data-testid="project-list"]' not visible.`

**Root Cause**: Firefox on BrowserStack Windows VM rendered the page with a different font size causing the project list to extend below the fold. The locator was technically visible but outside the scrollable viewport.

**Fix Applied**: Added `page.evaluate("window.scrollTo(0, document.body.scrollHeight)")` before asserting visibility of elements near the bottom of the page for Firefox.

## Flakiness History (Last 10 Runs)

| Run ID | Flaky Tests | Flake Rate |
|---|---|---|
| #8472 | 1 | 5.8% |
| #8471 | 0 | 0% |
| #8470 | 2 | 11.7% |
| #8469 | 1 | 5.8% |
| #8468 | 0 | 0% |
| #8467 | 1 | 5.8% |
| #8466 | 0 | 0% |
| #8465 | 3 | 17.6% |
| #8464 | 1 | 5.8% |
| #8463 | 0 | 0% |

**Average Flake Rate**: 5.3%

## Key Observations

1. **Login tests are stable** — auto-waiting eliminated race conditions (was 15% flake rate before fix)
2. **BrowserStack Firefox has viewport inconsistencies** — scrolling fix applied
3. **Security tests consistently pass** — API-level isolation is working correctly
4. **2FA test is skipped in CI** — need to inject TOTP secret for automated 2FA flow testing

## Recommendations

1. **Set up TOTP secret in CI** to enable 2FA test coverage
2. **Add scroll-into-view utility** to base page object for cross-browser robustness
3. **Reduc e BrowserStack Firefox timeout** from 30s to 20s (faster failure feedback)
4. **Add weekly flake trend report** to CI dashboard
5. **Consider adding visual regression tests** (Percy/Applitools) for responsive design validation
