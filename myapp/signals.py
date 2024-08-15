# myapp/signals.py

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import Like, Unlike, Review

@receiver(post_save, sender=Like)
def increment_like_count(sender, instance, created, **kwargs):
    if created:
        review = instance.review
        review.like_count += 1
        review.save()

@receiver(post_delete, sender=Like)
def decrement_like_count(sender, instance, **kwargs):
    review = instance.review
    if review.like_count > 0:
        review.like_count -= 1
        review.save()

@receiver(post_save, sender=Unlike)
def increment_unlike_count(sender, instance, created, **kwargs):
    if created:
        review = instance.review
        review.unlike_count += 1
        review.save()

@receiver(post_delete, sender=Unlike)
def decrement_unlike_count(sender, instance, **kwargs):
    review = instance.review
    if review.unlike_count > 0:
        review.unlike_count -= 1
        review.save()
