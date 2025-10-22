"""Correct ForeignKey table name for donation_offer

Revision ID: d66c6ec76b68
Revises: 487d72fd8601 # <-- Make sure this matches the 'Revises' ID in your file
Create Date: 2025-10-22 11:34:00.000000 # <-- Your date will be different

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd66c6ec76b68'
down_revision = '487d72fd8601' # <-- Make sure this matches the 'Revises' ID in your file
branch_labels = None
depends_on = None


def upgrade():
    # Drop the old constraints if they exist (using both potential old names)
    try:
        with op.batch_alter_table('chat_sessions', schema=None) as batch_op:
            batch_op.drop_constraint('chk_chat_subject', type_='check')
            print("Dropped constraint 'chk_chat_subject'")
    except Exception as e:
        print(f"Could not drop constraint 'chk_chat_subject' (may not exist): {e}")

    try:
        with op.batch_alter_table('chat_sessions', schema=None) as batch_op:
            batch_op.drop_constraint('chk_chat_subject_exclusive', type_='check')
            print("Dropped constraint 'chk_chat_subject_exclusive'")
    except Exception as e:
        print(f"Could not drop constraint 'chk_chat_subject_exclusive' (may not exist): {e}")

    # Add the new, correct constraint with the correct name
    with op.batch_alter_table('chat_sessions', schema=None) as batch_op:
        batch_op.create_check_constraint(
            'chk_chat_subject_exclusive', # The correct name from the model
            "(CASE WHEN trade_item_id IS NOT NULL THEN 1 ELSE 0 END + "
            " CASE WHEN donation_offer_id IS NOT NULL THEN 1 ELSE 0 END + "
            " CASE WHEN disaster_need_id IS NOT NULL THEN 1 ELSE 0 END) = 1"
        )
        print("Created constraint 'chk_chat_subject_exclusive'")


def downgrade():
    # Drop the new constraint
    try:
        with op.batch_alter_table('chat_sessions', schema=None) as batch_op:
            batch_op.drop_constraint('chk_chat_subject_exclusive', type_='check')
            print("Dropped constraint 'chk_chat_subject_exclusive' (downgrade)")
    except Exception as e:
         print(f"Could not drop constraint 'chk_chat_subject_exclusive' during downgrade: {e}")

    # Re-add the *original* constraint (assuming it existed before donation_offer_id)
    # Note: If your very first migration had a different constraint, adjust this.
    # This might fail if donation_offer_id still exists and isn't nullable,
    # but it's the logical reverse for the constraint itself.
    try:
        with op.batch_alter_table('chat_sessions', schema=None) as batch_op:
            batch_op.create_check_constraint(
                'chk_chat_subject', # Original name
                '(trade_item_id IS NOT NULL AND disaster_need_id IS NULL) OR (trade_item_id IS NULL AND disaster_need_id IS NOT NULL)'
            )
            print("Re-created original constraint 'chk_chat_subject' (downgrade)")
    except Exception as e:
        print(f"Could not re-create original constraint 'chk_chat_subject' during downgrade: {e}")