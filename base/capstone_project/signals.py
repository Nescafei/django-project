"""
Signal handlers for automatic cleanup of old media files.
This prevents storage bloat by deleting old files when users upload new ones.
"""
import os
from django.db.models.signals import pre_save, post_delete
from django.dispatch import receiver
from django.core.files.storage import default_storage
from .models import User, ForumMessage, Donation
import logging

logger = logging.getLogger(__name__)


@receiver(pre_save, sender=User)
def delete_old_profile_picture(sender, instance, **kwargs):
    """
    Delete old profile picture when user uploads a new one.
    This prevents accumulation of unused profile pictures in storage.
    """
    if not instance.pk:
        # New user, no old file to delete
        return

    try:
        old_user = User.objects.get(pk=instance.pk)
    except User.DoesNotExist:
        # User doesn't exist yet, nothing to delete
        return

    # Check if profile_picture has changed
    if old_user.profile_picture and instance.profile_picture:
        if old_user.profile_picture != instance.profile_picture:
            # Delete the old file
            if os.path.isfile(old_user.profile_picture.path):
                try:
                    os.remove(old_user.profile_picture.path)
                    logger.info(f"Deleted old profile picture: {old_user.profile_picture.path}")
                except Exception as e:
                    logger.error(f"Error deleting old profile picture: {str(e)}")


@receiver(pre_save, sender=User)
def delete_old_e_signature(sender, instance, **kwargs):
    """
    Delete old e-signature when user uploads a new one.
    This prevents accumulation of unused e-signature files in storage.
    """
    if not instance.pk:
        # New user, no old file to delete
        return

    try:
        old_user = User.objects.get(pk=instance.pk)
    except User.DoesNotExist:
        # User doesn't exist yet, nothing to delete
        return

    # Check if e_signature has changed
    if old_user.e_signature and instance.e_signature:
        if old_user.e_signature != instance.e_signature:
            # Delete the old file
            if os.path.isfile(old_user.e_signature.path):
                try:
                    os.remove(old_user.e_signature.path)
                    logger.info(f"Deleted old e-signature: {old_user.e_signature.path}")
                except Exception as e:
                    logger.error(f"Error deleting old e-signature: {str(e)}")


@receiver(post_delete, sender=User)
def delete_user_files_on_delete(sender, instance, **kwargs):
    """
    Delete user's profile picture and e-signature when user is deleted.
    This ensures no orphaned files remain in storage.
    """
    # Delete profile picture
    if instance.profile_picture:
        if os.path.isfile(instance.profile_picture.path):
            try:
                os.remove(instance.profile_picture.path)
                logger.info(f"Deleted profile picture on user deletion: {instance.profile_picture.path}")
            except Exception as e:
                logger.error(f"Error deleting profile picture on user deletion: {str(e)}")

    # Delete e-signature
    if instance.e_signature:
        if os.path.isfile(instance.e_signature.path):
            try:
                os.remove(instance.e_signature.path)
                logger.info(f"Deleted e-signature on user deletion: {instance.e_signature.path}")
            except Exception as e:
                logger.error(f"Error deleting e-signature on user deletion: {str(e)}")


@receiver(pre_save, sender=ForumMessage)
def delete_old_forum_image(sender, instance, **kwargs):
    """
    Delete old forum message image when a new one is uploaded.
    This prevents accumulation of unused forum images in storage.
    """
    if not instance.pk:
        # New message, no old file to delete
        return

    try:
        old_message = ForumMessage.objects.get(pk=instance.pk)
    except ForumMessage.DoesNotExist:
        # Message doesn't exist yet, nothing to delete
        return

    # Check if image has changed
    if old_message.image and instance.image:
        if old_message.image != instance.image:
            # Delete the old file
            if os.path.isfile(old_message.image.path):
                try:
                    os.remove(old_message.image.path)
                    logger.info(f"Deleted old forum image: {old_message.image.path}")
                except Exception as e:
                    logger.error(f"Error deleting old forum image: {str(e)}")


@receiver(post_delete, sender=ForumMessage)
def delete_forum_image_on_delete(sender, instance, **kwargs):
    """
    Delete forum message image when message is deleted.
    This ensures no orphaned files remain in storage.
    """
    if instance.image:
        if os.path.isfile(instance.image.path):
            try:
                os.remove(instance.image.path)
                logger.info(f"Deleted forum image on message deletion: {instance.image.path}")
            except Exception as e:
                logger.error(f"Error deleting forum image on message deletion: {str(e)}")


@receiver(pre_save, sender=Donation)
def delete_old_donation_receipt(sender, instance, **kwargs):
    """
    Delete old donation receipt when a new one is uploaded.
    This prevents accumulation of unused receipt files in storage.
    """
    if not instance.pk:
        # New donation, no old file to delete
        return

    try:
        old_donation = Donation.objects.get(pk=instance.pk)
    except Donation.DoesNotExist:
        # Donation doesn't exist yet, nothing to delete
        return

    # Check if receipt has changed
    if old_donation.receipt and instance.receipt:
        if old_donation.receipt != instance.receipt:
            # Delete the old file
            if os.path.isfile(old_donation.receipt.path):
                try:
                    os.remove(old_donation.receipt.path)
                    logger.info(f"Deleted old donation receipt: {old_donation.receipt.path}")
                except Exception as e:
                    logger.error(f"Error deleting old donation receipt: {str(e)}")


@receiver(post_delete, sender=Donation)
def delete_donation_receipt_on_delete(sender, instance, **kwargs):
    """
    Delete donation receipt when donation is deleted.
    This ensures no orphaned files remain in storage.
    """
    if instance.receipt:
        if os.path.isfile(instance.receipt.path):
            try:
                os.remove(instance.receipt.path)
                logger.info(f"Deleted donation receipt on deletion: {instance.receipt.path}")
            except Exception as e:
                logger.error(f"Error deleting donation receipt on deletion: {str(e)}")


def cleanup_qr_codes(user_id=None):
    """
    Utility function to clean up QR codes.
    Can be called manually or scheduled as a periodic task.
    
    Args:
        user_id: If provided, only delete QR codes for this user.
                 If None, delete all QR codes (useful for periodic cleanup).
    """
    from django.conf import settings
    
    qr_codes_dir = os.path.join(settings.MEDIA_ROOT, 'qr_codes')
    
    if not os.path.exists(qr_codes_dir):
        return
    
    try:
        if user_id:
            # Delete QR codes for specific user
            pattern = f'qr_{user_id}_'
            for filename in os.listdir(qr_codes_dir):
                if filename.startswith(pattern):
                    file_path = os.path.join(qr_codes_dir, filename)
                    try:
                        os.remove(file_path)
                        logger.info(f"Deleted QR code: {file_path}")
                    except Exception as e:
                        logger.error(f"Error deleting QR code {file_path}: {str(e)}")
        else:
            # Delete all QR codes (for periodic cleanup)
            for filename in os.listdir(qr_codes_dir):
                if filename.startswith('qr_') and filename.endswith('.png'):
                    file_path = os.path.join(qr_codes_dir, filename)
                    try:
                        os.remove(file_path)
                        logger.info(f"Deleted QR code: {file_path}")
                    except Exception as e:
                        logger.error(f"Error deleting QR code {file_path}: {str(e)}")
    except Exception as e:
        logger.error(f"Error during QR code cleanup: {str(e)}")
