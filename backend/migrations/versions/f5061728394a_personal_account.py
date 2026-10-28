"""Store only a salted password hash for the configured personal account."""
from alembic import op
import sqlalchemy as sa

revision = 'f5061728394a'
down_revision = 'e4f506172839'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('personal_account',
                    sa.Column('id', sa.String(16), primary_key=True),
                    sa.Column('email', sa.String(254), nullable=False),
                    sa.Column('password_hash', sa.String(256), nullable=False))


def downgrade():
    op.drop_table('personal_account')
