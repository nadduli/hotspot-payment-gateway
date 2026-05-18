"""transaction_mikrotik_encryption

Revision ID: f29672c8ed8f
Revises: a5cb24869a7c
Create Date: 2026-05-19 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

from src.core.encryption import decrypt_value, encrypt_value


# revision identifiers, used by Alembic.
revision = "f29672c8ed8f"
down_revision = "a5cb24869a7c"
branch_labels = None
depends_on = None


def _recreate_foreign_key(
    connection,
    table_name: str,
    columns: list[str],
    referred_table: str,
    referred_columns: list[str],
    ondelete: str | None,
) -> None:
    inspector = sa.inspect(connection)
    for fk in inspector.get_foreign_keys(table_name):
        if fk["constrained_columns"] == columns:
            if fk["name"]:
                op.drop_constraint(fk["name"], table_name, type_="foreignkey")
            break

    op.create_foreign_key(
        f"fk_{table_name}_{'_'.join(columns)}",
        table_name,
        referred_table,
        columns,
        referred_columns,
        ondelete=ondelete,
    )


def upgrade() -> None:
    op.add_column(
        "transactions",
        sa.Column("mikrotik_username_enc", sa.Text(), nullable=True),
    )
    op.add_column(
        "transactions",
        sa.Column("mikrotik_password_enc", sa.Text(), nullable=True),
    )

    connection = op.get_bind()
    result = connection.execute(
        sa.text(
            "SELECT id, mikrotik_username, mikrotik_password FROM transactions"
        )
    )

    batch_size = 500
    while True:
        rows = result.fetchmany(batch_size)
        if not rows:
            break
        params = [
            {
                "id": row.id,
                "username_enc": encrypt_value(row.mikrotik_username),
                "password_enc": encrypt_value(row.mikrotik_password),
            }
            for row in rows
        ]
        connection.execute(
            sa.text(
                "UPDATE transactions SET mikrotik_username_enc = :username_enc, "
                "mikrotik_password_enc = :password_enc WHERE id = :id"
            ),
            params,
        )

    op.drop_column("transactions", "mikrotik_username")
    op.drop_column("transactions", "mikrotik_password")

    _recreate_foreign_key(
        connection,
        "transactions",
        ["plan_id"],
        "plans",
        ["id"],
        ondelete="RESTRICT",
    )
    _recreate_foreign_key(
        connection,
        "transactions",
        ["router_id"],
        "routers",
        ["id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.add_column(
        "transactions",
        sa.Column("mikrotik_username", sa.String(length=80), nullable=True),
    )
    op.add_column(
        "transactions",
        sa.Column("mikrotik_password", sa.String(length=80), nullable=True),
    )

    connection = op.get_bind()
    result = connection.execute(
        sa.text(
            "SELECT id, mikrotik_username_enc, mikrotik_password_enc FROM transactions"
        )
    )

    batch_size = 500
    while True:
        rows = result.fetchmany(batch_size)
        if not rows:
            break
        params = [
            {
                "id": row.id,
                "username": decrypt_value(row.mikrotik_username_enc),
                "password": decrypt_value(row.mikrotik_password_enc),
            }
            for row in rows
        ]
        connection.execute(
            sa.text(
                "UPDATE transactions SET mikrotik_username = :username, "
                "mikrotik_password = :password WHERE id = :id"
            ),
            params,
        )

    op.drop_column("transactions", "mikrotik_username_enc")
    op.drop_column("transactions", "mikrotik_password_enc")

    _recreate_foreign_key(
        connection,
        "transactions",
        ["plan_id"],
        "plans",
        ["id"],
        ondelete=None,
    )
    _recreate_foreign_key(
        connection,
        "transactions",
        ["router_id"],
        "routers",
        ["id"],
        ondelete=None,
    )
