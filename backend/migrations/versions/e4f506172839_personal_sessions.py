"""Add revocable personal login sessions without changing audit data."""
from alembic import op
import sqlalchemy as sa

revision = 'e4f506172839'
down_revision = 'd3e4f5061723'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('auth_sessions',
                    sa.Column('token_hash', sa.String(64), primary_key=True),
                    sa.Column('credential_revision', sa.String(64), nullable=False),
                    sa.Column('expires_at', sa.String(40), nullable=False))
    op.create_index('ix_auth_sessions_expires_at', 'auth_sessions', ['expires_at'])


def downgrade():
    op.drop_index('ix_auth_sessions_expires_at', table_name='auth_sessions')
    op.drop_table('auth_sessions')
