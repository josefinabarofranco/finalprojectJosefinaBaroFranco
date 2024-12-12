from django.db import models
from django.contrib.auth.models import User


class SavedURL(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='saved_urls')
    url = models.URLField()
    created_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return self.url