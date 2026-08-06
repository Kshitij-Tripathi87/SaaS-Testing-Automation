"""Tenant isolation testing primitives.

Public API:
    IsolationPattern, IsolationScenario,
    verify_cross_tenant_access, assert_summary,
    VerificationRecord, VerificationSummary
"""

from tenant_shield.isolation.patterns import IsolationPattern
from tenant_shield.isolation.result import VerificationRecord, VerificationSummary
from tenant_shield.isolation.scenario import IsolationScenario
from tenant_shield.isolation.verifier import (
    assert_summary,
    verify_cross_tenant_access,
    verify_delete_denied,
    verify_list_excludes,
    verify_modify_denied,
    verify_positive_control,
    verify_read,
)

__all__ = [
    "IsolationPattern",
    "IsolationScenario",
    "VerificationRecord",
    "VerificationSummary",
    "verify_cross_tenant_access",
    "verify_read",
    "verify_list_excludes",
    "verify_modify_denied",
    "verify_delete_denied",
    "verify_positive_control",
    "assert_summary",
]
