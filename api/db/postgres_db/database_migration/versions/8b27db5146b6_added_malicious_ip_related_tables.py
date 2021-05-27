"""Added malicious Ip related tables.

Revision ID: 8b27db5146b6
Revises: be01f1a9f59e
Create Date: 2021-04-23 12:25:44.147852

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8b27db5146b6'
down_revision = '350c66f32786'
branch_labels = None
depends_on = None


maliciousIPSourceEnum = sa.Enum('firewall_inbound_traffic', 'firewall_outbound_traffic', 'firewall_ddos_attack', 'honeypot', 'dmz', name='enum_malicious_ip_sources')

def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    print("Creating malicious_ips table.")
    op.create_table('malicious_ips',
        sa.Column('ip', sa.String(length=50), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('ip')
    )

    print("Creating ip_location table.")
    op.create_table('ip_location',
        sa.Column('ip', sa.String(length=50), sa.ForeignKey('malicious_ips.ip', ondelete="cascade"), nullable=False),
        sa.Column('received_from', sa.String(length=255), sa.ForeignKey('users.username'), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('lat', sa.Float, nullable=True),
        sa.Column('lon', sa.Float, nullable=True),
        sa.Column('country', sa.String(length=50), nullable=True),
        sa.Column('city', sa.String(length=50), nullable=True),
        sa.Column('region', sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint('ip', 'received_from', name='pk_ip_account'),
        sa.Index('index_ip_location', 'ip')
    )

    print("Creating malicious_ip_sources table.")
    op.create_table('malicious_ip_sources',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('received_from', sa.String(length=255), sa.ForeignKey('users.username'), nullable=False),
        sa.Column('source', maliciousIPSourceEnum, nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('received_from', 'source', name='unique_sources'),
        sa.Index('index_source_account', 'received_from')
    )

    print("Creating malicious_ip_information table.")
    op.create_table('malicious_ip_information',
        sa.Column('bad_actor', sa.String(length=50), sa.ForeignKey('malicious_ips.ip', ondelete="cascade"), nullable=False),
        sa.Column('source_id', sa.Integer(), sa.ForeignKey('malicious_ip_sources.id', ondelete="cascade"), nullable=False),
        sa.Column('field', sa.String(length=50), nullable=False),
        sa.Column('value', sa.String(length=5000), nullable=False),
        sa.Column('last_detected', sa.DateTime(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('bad_actor', 'source_id', 'field', 'value', name='pk_mal_ip_information'),
        sa.Index('index_info_bad_actor', 'bad_actor'),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('malicious_ip_information')
    op.drop_table('malicious_ip_sources')
    op.drop_table('ip_location')
    op.drop_table('malicious_ips')
    maliciousIPSourceEnum.drop(op.get_bind(), checkfirst=False)
    # ### end Alembic commands ###
