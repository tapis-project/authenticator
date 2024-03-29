"""empty message

Revision ID: 9983be60f4e8
Revises: 0c783d9da131
Create Date: 2022-08-29 20:00:49.969933

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9983be60f4e8'
down_revision = '0c783d9da131'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('access_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('jti', sa.String(length=50), nullable=False),
    sa.Column('subject', sa.String(length=80), nullable=False),
    sa.Column('tenant_id', sa.String(length=50), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('client_id', sa.String(length=80), nullable=True),
    sa.Column('grant_type', sa.String(length=80), nullable=False),
    sa.Column('token_ttl', sa.Integer(), nullable=False),
    sa.Column('with_refresh', sa.Boolean(), nullable=False),
    sa.Column('token_create_time', sa.DateTime(), nullable=False),
    sa.Column('token_expiry_time', sa.DateTime(), nullable=False),
    sa.Column('token_revoked', sa.Boolean(), nullable=False),
    sa.Column('token_revoked_time', sa.DateTime(), nullable=True),
    sa.Column('last_update_time', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['client_id'], ['clients.client_id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('refresh_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('jti', sa.String(length=50), nullable=False),
    sa.Column('subject', sa.String(length=80), nullable=False),
    sa.Column('tenant_id', sa.String(length=50), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('client_id', sa.String(length=80), nullable=True),
    sa.Column('grant_type', sa.String(length=80), nullable=False),
    sa.Column('token_ttl', sa.Integer(), nullable=False),
    sa.Column('token_create_time', sa.DateTime(), nullable=False),
    sa.Column('token_expiry_time', sa.DateTime(), nullable=False),
    sa.Column('token_revoked', sa.Boolean(), nullable=False),
    sa.Column('token_revoked_time', sa.DateTime(), nullable=True),
    sa.Column('last_update_time', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['client_id'], ['clients.client_id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('refresh_tokens')
    op.drop_table('access_tokens')
    # ### end Alembic commands ###
