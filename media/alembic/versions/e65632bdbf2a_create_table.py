"""create table

Revision ID: e65632bdbf2a
Revises: 
Create Date: 2018-11-24 10:49:36.188393

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e65632bdbf2a'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'task_record',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('task_uuid', sa.String(256), unique=True),
        sa.Column('production_date', sa.DateTime()),
        sa.Column('media_uuid', sa.String(256)),
        sa.Column('task_ext_inf', sa.TEXT()),
        sa.Column('occupy_size', sa.BigInteger(), default=0),
        sa.Column('file_count', sa.BigInteger(), default=0),
        sa.Column('deleting', sa.Boolean(), default=False),
        sa.Column('successful', sa.Boolean(), default=False),
        sa.Column('overwritedata', sa.Boolean(), default=False),
    )


def downgrade():
    pass
