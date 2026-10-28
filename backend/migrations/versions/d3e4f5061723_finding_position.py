"""Preserve XML result order, including reports already imported."""
from alembic import op
import sqlalchemy as sa
from defusedxml import ElementTree

revision = "d3e4f5061723"
down_revision = "c2d3e4f50612"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("findings", sa.Column("position", sa.Integer(), nullable=False, server_default="0"))
    connection = op.get_bind()
    imports = sa.table("imports", sa.column("id", sa.String()), sa.column("content", sa.LargeBinary()))
    findings = sa.table("findings", sa.column("import_id", sa.String()),
                        sa.column("external_id", sa.String()), sa.column("position", sa.Integer()))
    last_id = ""
    while True:
        batch = connection.execute(sa.select(imports).where(imports.c.id > last_id).order_by(imports.c.id).limit(20)).all()
        if not batch:
            break
        for report_id, content in batch:
            root = ElementTree.fromstring(content, forbid_dtd=True, forbid_entities=True, forbid_external=True)
            for position, result in enumerate(root.findall(".//results/result"), start=1):
                connection.execute(findings.update().where(
                    findings.c.import_id == report_id,
                    findings.c.external_id == (result.get("id") or "").strip(),
                ).values(position=position))
        last_id = batch[-1][0]


def downgrade():
    op.drop_column("findings", "position")
