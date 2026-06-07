"""harden secret schema

Revision ID: 003_harden_secret_schema
Revises: 002_create_secret_tables
Create Date: 2026-06-06 00:00:00
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "003_harden_secret_schema"
down_revision: str | None = "002_create_secret_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("uq_secrets_path", "secrets", type_="unique")

    op.create_index(
        "uq_secrets_path_active",
        "secrets",
        ["path"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )

    op.create_check_constraint(
        "ck_secrets_current_version_positive",
        "secrets",
        "current_version >= 1",
    )

    op.create_check_constraint(
        "ck_secret_versions_version_positive",
        "secret_versions",
        "version >= 1",
    )

    op.drop_constraint(
        "ck_access_policies_access_policy_capability_allowed",
        "access_policies",
        type_="check",
    )

    op.create_check_constraint(
        "ck_access_policies_capability_allowed",
        "access_policies",
        "capability IN ('read', 'update', 'delete', 'rotate', 'manage_policy')",
    )

    op.create_check_constraint(
        "ck_audit_logs_actor_type_allowed",
        "audit_logs",
        "actor_type IN ('user', 'service_account', 'system', 'anonymous')",
    )

    op.create_check_constraint(
        "ck_audit_logs_status_allowed",
        "audit_logs",
        "status IN ('success', 'denied', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_audit_logs_status_allowed", "audit_logs", type_="check")
    op.drop_constraint("ck_audit_logs_actor_type_allowed", "audit_logs", type_="check")

    op.drop_constraint(
        "ck_access_policies_capability_allowed",
        "access_policies",
        type_="check",
    )
    op.create_check_constraint(
        "ck_access_policies_access_policy_capability_allowed",
        "access_policies",
        "capability IN ('read', 'create', 'update', 'delete', 'rotate', 'manage_policy')",
    )

    op.drop_constraint(
        "ck_secret_versions_version_positive",
        "secret_versions",
        type_="check",
    )
    op.drop_constraint(
        "ck_secrets_current_version_positive",
        "secrets",
        type_="check",
    )

    op.drop_index("uq_secrets_path_active", table_name="secrets")
    op.create_unique_constraint("uq_secrets_path", "secrets", ["path"])
