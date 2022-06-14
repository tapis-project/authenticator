"""empty message

Revision ID: 0c783d9da131
Revises: 31fdce5367d2
Create Date: 2022-06-02 19:29:26.564655

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0c783d9da131'
down_revision = '31fdce5367d2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('clients', 'active',
               existing_type=sa.BOOLEAN(),
               nullable=False)
    op.add_column('tenantconfig', sa.Column('impers_oauth_client_id', sa.String(length=50), nullable=True))
    op.add_column('tenantconfig', sa.Column('impers_oauth_client_secret', sa.String(length=50), nullable=True))
    op.add_column('tenantconfig', sa.Column('impersadmin_username', sa.String(length=50), nullable=True))
    op.add_column('tenantconfig', sa.Column('impersadmin_password', sa.String(length=50), nullable=True))
    op.add_column('tenantconfig', sa.Column('token_url', sa.String(length=255), nullable=True))

    op.execute('UPDATE tenantconfig SET impers_oauth_client_id=""')
    op.execute('UPDATE tenantconfig SET impers_oauth_client_secret=""')
    op.execute('UPDATE tenantconfig SET impersadmin_username=""')
    op.execute('UPDATE tenantconfig SET impersadmin_password=""')
    op.execute('UPDATE tenantconfig SET token_url=""')

    op.alter_column('tenantconfig', sa.Column('impers_oauth_client_id', sa.String(length=50), nullable=False))
    op.alter_column('tenantconfig', sa.Column('impers_oauth_client_secret', sa.String(length=50), nullable=False))
    op.alter_column('tenantconfig', sa.Column('impersadmin_username', sa.String(length=50), nullable=False))
    op.alter_column('tenantconfig', sa.Column('impersadmin_password', sa.String(length=50), nullable=False))
    op.alter_column('tenantconfig', sa.Column('token_url', sa.String(length=255), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('tenantconfig', 'token_url')
    op.drop_column('tenantconfig', 'impersadmin_password')
    op.drop_column('tenantconfig', 'impers_oauth_password')
    op.drop_column('tenantconfig', 'impers_oauth_client')
    op.alter_column('clients', 'active',
               existing_type=sa.BOOLEAN(),
               nullable=True)
    # ### end Alembic commands ###