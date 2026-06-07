"""remove update capability

Revision ID: 005_remove_update_capability
Revises: 004_normalize_roles_and_identity
Create Date: 2026-06-07
"""

from collections.abc import Sequence

from alembic import op


revision: str = "005_remove_update_capability"
down_revision: str | None = "004_normalize_roles_and_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("DELETE FROM access_policies WHERE capability = 'update'")

    op.execute(
        "ALTER TABLE access_policies "
        "DROP CONSTRAINT IF EXISTS ck_access_policies_capability_allowed"
    )

    op.create_check_constraint(
        "ck_access_policies_capability_allowed",
        "access_policies",
        "capability IN ('read', 'delete', 'rotate', 'manage_policy')",
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE access_policies "
        "DROP CONSTRAINT IF EXISTS ck_access_policies_capability_allowed"
    )

    op.create_check_constraint(
        "ck_access_policies_capability_allowed",
        "access_policies",
        "capability IN ('read', 'update', 'delete', 'rotate', 'manage_policy')",
    )