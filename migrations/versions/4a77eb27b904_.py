"""empty message

Revision ID: 4a77eb27b904
Revises: 503038e5d197
Create Date: 2021-06-13 18:33:00.558920

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4a77eb27b904'
down_revision = '503038e5d197'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('tenantconfig',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('tenant_id', sa.String(length=50), nullable=False),
    sa.Column('allowable_grant_types', sa.String(length=500), nullable=False),
    sa.Column('use_ldap', sa.Boolean(), nullable=False),
    sa.Column('use_token_webapp', sa.Boolean(), nullable=False),
    sa.Column('mfa_config', sa.String(length=2500), nullable=False),
    sa.Column('default_access_token_ttl', sa.Integer(), nullable=True),
    sa.Column('default_refresh_token_ttl', sa.Integer(), nullable=True),
    sa.Column('max_access_token_ttl', sa.Integer(), nullable=True),
    sa.Column('max_refresh_token_ttl', sa.Integer(), nullable=True),
    sa.Column('custom_idp_configuration', sa.String(length=2500), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('tenantconfig')
    # ### end Alembic commands ###