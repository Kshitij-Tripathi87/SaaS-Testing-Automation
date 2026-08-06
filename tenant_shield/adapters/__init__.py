"""Tenant Shield adapters: pluggable tenant identity + auth.

Public registry API:

    from tenant_shield.adapters import AdapterRegistry
    resolver, provider = AdapterRegistry.from_yaml("adapters.yaml")
"""

from tenant_shield.adapters.auth_bearer import BearerAuthProvider
from tenant_shield.adapters.auth_session import APIKeyAuthProvider, SessionAuthProvider
from tenant_shield.adapters.protocols import AuthProvider, TenantAwareRequest, TenantResolver
from tenant_shield.adapters.registry import AdapterRegistry, AUTH_PROVIDERS, RESOLVERS
from tenant_shield.adapters.tenant_header import HeaderTenantResolver
from tenant_shield.adapters.tenant_jwt import JWTTenantResolver
from tenant_shield.adapters.tenant_subdomain import SubdomainTenantResolver

__all__ = [
    "AdapterRegistry",
    "AUTH_PROVIDERS",
    "RESOLVERS",
    "TenantResolver",
    "AuthProvider",
    "TenantAwareRequest",
    "HeaderTenantResolver",
    "SubdomainTenantResolver",
    "JWTTenantResolver",
    "BearerAuthProvider",
    "SessionAuthProvider",
    "APIKeyAuthProvider",
]
