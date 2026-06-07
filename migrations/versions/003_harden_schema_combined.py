"""harden schema combined

Revision ID: 003_harden_schema_combined
Revises: 002_create_secret_tables
Create Date: 2026-06-07
"""

from collections.abc import Sequence
import uuid

from alembic import op
import sqlalchemy as sa


revision: str = "003_harden_schema_combined"
down_revision: str | None = "002_create_secret_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


OWNER_CAPABILITIES = (
    "read",
    "delete",
    "rotate",
    "manage_policy",
)


def _drop_constraint_if_exists(table_name: str, constraint_name: str) -> None:
    op.execute(
        f"ALTER TABLE {table_name} "
        f"DROP CONSTRAINT IF EXISTS {constraint_name}"
    )


def _drop_index_if_exists(index_name: str) -> None:
    op.execute(f"DROP INDEX IF EXISTS {index_name}")


def _add_check_constraint_if_not_exists(
    table_name: str,
    constraint_name: str,
    condition: str,
) -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = '{constraint_name}'
            ) THEN
                ALTER TABLE {table_name}
                ADD CONSTRAINT {constraint_name}
                CHECK ({condition});
            END IF;
        END
        $$;
        """
    )


def _merge_duplicate_roles() -> None:
    # Если вдруг есть роли admin/Admin/ADMIN, оставляем одну,
    # переносим principal_roles на нее, а дубликаты удаляем.
    op.execute(
        """
        WITH ranked_roles AS (
            SELECT
                id,
                lower(trim(name)) AS normalized_name,
                first_value(id) OVER (
                    PARTITION BY lower(trim(name))
                    ORDER BY id
                ) AS keep_id,
                row_number() OVER (
                    PARTITION BY lower(trim(name))
                    ORDER BY id
                ) AS rn
            FROM roles
        ),
        duplicate_links AS (
            SELECT
                pr.principal_id,
                rr.id AS old_role_id,
                rr.keep_id AS keep_role_id
            FROM principal_roles pr
            JOIN ranked_roles rr ON rr.id = pr.role_id
            WHERE rr.rn > 1
        )
        DELETE FROM principal_roles pr
        USING duplicate_links dl
        WHERE pr.principal_id = dl.principal_id
          AND pr.role_id = dl.old_role_id
          AND EXISTS (
              SELECT 1
              FROM principal_roles existing_pr
              WHERE existing_pr.principal_id = dl.principal_id
                AND existing_pr.role_id = dl.keep_role_id
          );
        """
    )

    op.execute(
        """
        WITH ranked_roles AS (
            SELECT
                id,
                lower(trim(name)) AS normalized_name,
                first_value(id) OVER (
                    PARTITION BY lower(trim(name))
                    ORDER BY id
                ) AS keep_id,
                row_number() OVER (
                    PARTITION BY lower(trim(name))
                    ORDER BY id
                ) AS rn
            FROM roles
        )
        UPDATE principal_roles pr
        SET role_id = rr.keep_id
        FROM ranked_roles rr
        WHERE pr.role_id = rr.id
          AND rr.rn > 1;
        """
    )

    op.execute(
        """
        WITH ranked_roles AS (
            SELECT
                id,
                row_number() OVER (
                    PARTITION BY lower(trim(name))
                    ORDER BY id
                ) AS rn
            FROM roles
        )
        DELETE FROM roles r
        USING ranked_roles rr
        WHERE r.id = rr.id
          AND rr.rn > 1;
        """
    )

    op.execute("UPDATE roles SET name = lower(trim(name))")


def _backfill_owner_policies() -> None:
    bind = op.get_bind()

    secrets = bind.execute(
        sa.text(
            """
            SELECT id, owner_principal_id
            FROM secrets
            WHERE is_deleted = false
            """
        )
    ).mappings().all()

    for secret in secrets:
        for capability in OWNER_CAPABILITIES:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO access_policies (
                        id,
                        principal_id,
                        secret_id,
                        capability,
                        created_by
                    )
                    SELECT
                        :id,
                        :principal_id,
                        :secret_id,
                        :capability,
                        :created_by
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM access_policies
                        WHERE principal_id = :principal_id
                          AND secret_id = :secret_id
                          AND capability = :capability
                    )
                    """
                ),
                {
                    "id": uuid.uuid4(),
                    "principal_id": secret["owner_principal_id"],
                    "secret_id": secret["id"],
                    "capability": capability,
                    "created_by": secret["owner_principal_id"],
                },
            )


def upgrade() -> None:
    # 1. Secret.path + soft delete.
    _drop_constraint_if_exists("secrets", "uq_secrets_path")
    _drop_constraint_if_exists("secrets", "secrets_path_key")
    _drop_index_if_exists("uq_secrets_path_active")

    op.create_index(
        "uq_secrets_path_active",
        "secrets",
        ["path"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )

    # 2. Version constraints.
    _add_check_constraint_if_not_exists(
        table_name="secrets",
        constraint_name="ck_secrets_current_version_positive",
        condition="current_version >= 1",
    )

    _add_check_constraint_if_not_exists(
        table_name="secret_versions",
        constraint_name="ck_secret_versions_version_positive",
        condition="version >= 1",
    )

    # 3. AccessPolicy capabilities:
    #    убираем create и update.
    op.execute(
        """
        DELETE FROM access_policies
        WHERE capability IN ('create', 'update')
        """
    )

    _drop_constraint_if_exists(
        "access_policies",
        "ck_access_policies_access_policy_capability_allowed",
    )
    _drop_constraint_if_exists(
        "access_policies",
        "access_policy_capability_allowed",
    )
    _drop_constraint_if_exists(
        "access_policies",
        "ck_access_policies_capability_allowed",
    )

    op.create_check_constraint(
        "ck_access_policies_capability_allowed",
        "access_policies",
        "capability IN ('read', 'delete', 'rotate', 'manage_policy')",
    )

    # 4. Audit constraints.
    _add_check_constraint_if_not_exists(
        table_name="audit_logs",
        constraint_name="ck_audit_logs_actor_type_allowed",
        condition=(
            "actor_type IN "
            "('user', 'service_account', 'system', 'anonymous')"
        ),
    )

    _add_check_constraint_if_not_exists(
        table_name="audit_logs",
        constraint_name="ck_audit_logs_status_allowed",
        condition="status IN ('success', 'denied', 'failed')",
    )

    # 5. Normalize roles and make role names case-insensitive unique.
    _drop_constraint_if_exists("roles", "roles_name_key")
    _drop_constraint_if_exists("roles", "uq_roles_name")
    _drop_index_if_exists("roles_name_key")
    _drop_index_if_exists("uq_roles_name")
    _drop_index_if_exists("roles_name_lower_uq")

    _merge_duplicate_roles()

    op.create_index(
        "roles_name_lower_uq",
        "roles",
        [sa.text("lower(name)")],
        unique=True,
    )

    # 6. Since owner is now checked through access_policies,
    #    existing secrets must receive owner policies.
    _backfill_owner_policies()


def downgrade() -> None:
    _drop_index_if_exists("roles_name_lower_uq")

    op.create_unique_constraint(
        "uq_roles_name",
        "roles",
        ["name"],
    )

    _drop_constraint_if_exists(
        "audit_logs",
        "ck_audit_logs_status_allowed",
    )
    _drop_constraint_if_exists(
        "audit_logs",
        "ck_audit_logs_actor_type_allowed",
    )

    _drop_constraint_if_exists(
        "access_policies",
        "ck_access_policies_capability_allowed",
    )

    op.create_check_constraint(
        "ck_access_policies_access_policy_capability_allowed",
        "access_policies",
        "capability IN "
        "('read', 'create', 'update', 'delete', 'rotate', 'manage_policy')",
    )

    _drop_constraint_if_exists(
        "secret_versions",
        "ck_secret_versions_version_positive",
    )
    _drop_constraint_if_exists(
        "secrets",
        "ck_secrets_current_version_positive",
    )

    _drop_index_if_exists("uq_secrets_path_active")

    op.create_unique_constraint(
        "uq_secrets_path",
        "secrets",
        ["path"],
    )