"""Record CVE applicability decisions without changing historical snapshots."""
from alembic import op
import sqlalchemy as sa
revision = "c2d3e4f50612"
down_revision = "b1c2d3e4f501"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("cve_reviews",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.String(36), nullable=False),
        sa.Column("cve", sa.String(32), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("reviewer", sa.String(160), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("reviewed_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["finding_id", "cve"], ["finding_cves.finding_id", "finding_cves.cve"]),
        sa.CheckConstraint("status IN ('pending', 'applicable', 'not_applicable')"),
        sa.CheckConstraint("length(trim(reviewer)) > 0 AND length(trim(rationale)) > 0"))
    op.create_index("ix_cve_reviews_finding_id", "cve_reviews", ["finding_id"])


def downgrade():
    op.drop_index("ix_cve_reviews_finding_id", table_name="cve_reviews")
    op.drop_table("cve_reviews")
