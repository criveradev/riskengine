"""Preserve original scanner vectors without reinterpreting historical runs."""
from alembic import op
import sqlalchemy as sa
from defusedxml import ElementTree

revision = "b1c2d3e4f501"
down_revision = "394376e43314"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("findings", sa.Column("original_vectors", sa.JSON(), nullable=True))
    connection = op.get_bind()
    imports = sa.table("imports", sa.column("id", sa.String()), sa.column("content", sa.LargeBinary()))
    findings = sa.table("findings", sa.column("import_id", sa.String()), sa.column("external_id", sa.String()), sa.column("original_vectors", sa.JSON()))
    # Page through stored reports so a large archive is not loaded into memory.
    last_id = ""
    while True:
        batch = connection.execute(sa.select(imports).where(imports.c.id > last_id).order_by(imports.c.id).limit(20)).all()
        if not batch:
            break
        for report_id, content in batch:
            root = ElementTree.fromstring(content, forbid_dtd=True, forbid_entities=True, forbid_external=True)
            for result in root.findall(".//results/result"):
                vectors = [v.text.strip() for v in result.findall("nvt/severities/severity/value") if v.text]
                for part in result.findtext("nvt/tags", "").split("|"):
                    key, sep, value = part.partition("=")
                    if sep and key.strip() in {"cvss_base_vector", "cvss3_base_vector"}:
                        vectors.append(value.strip())
                connection.execute(findings.update().where(findings.c.import_id == report_id, findings.c.external_id == result.get("id")).values(original_vectors=sorted(set(vectors))))
        last_id = batch[-1][0]


def downgrade():
    op.drop_column("findings", "original_vectors")
