""""
Migrations for the 1.3.4 Authenticator release
"""

from alembic import op
import psycopg2
import sqlalchemy as sa
from tapisservice.config import conf
from tapisservice.logs import get_logger
logger = get_logger(__name__)


# revision identifiers, used by Alembic.
revision = '1.3.4'
down_revision = '6df17a83c1fc'
branch_labels = None
depends_on = None


def upgrade():
    pass
    conn = op.get_bind()
    conn.execute("ALTER TABLE public.device_codes ALTER COLUMN username DROP NOT NULL;")
    conn.execute("ALTER TABLE public.device_codes ALTER COLUMN verification_uri TYPE varchar(500);")


def downgrade():
    conn = op.get_bind()
    conn.execute("ALTER TABLE public.device_codes ALTER COLUMN username ADD NOT NULL;")
    conn.execute("ALTER TABLE public.device_codes ALTER COLUMN verification_uri TYPE varchar(80);")

