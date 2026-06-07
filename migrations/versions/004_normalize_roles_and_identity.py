"""normalize roles and identity

Revision ID: 004_normalize_roles_and_identity
Revises: 003_harden_secret_schema
Create Date: 2026-06-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "004_normalize_roles_and_identity"
down_revision: str | None = "003_harden_secret_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Normalize existing role names.
    op.execute("UPDATE roles SET name = lower(trim(name))")

    # Drop old unique constraints/indexes if they exist.
    op.execute("ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_key")
    op.execute("ALTER TABLE roles DROP CONSTRAINT IF EXISTS uq_roles_name")
    op.execute("DROP INDEX IF EXISTS roles_name_key")
    op.execute("DROP INDEX IF EXISTS uq_roles_name")

    # Create case-insensitive unique index.
    op.create_index(
        "roles_name_lower_uq",
        "roles",
        [sa.text("lower(name)")],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("roles_name_lower_uq", table_name="roles")

    op.create_unique_constraint(
        "uq_roles_name",
        "roles",
        ["name"],
    )
