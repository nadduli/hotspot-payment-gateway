import uuid

# Single-tenant Phase A uses this fixed UUID as the implicit owner of every
# row. The migration seeds a tenant with this id; the conftest does the same
# for SQLite. Multi-tenant Phase B replaces hardcoded references with a
# request-state tenant resolved from the subdomain (see spec §7).
DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
