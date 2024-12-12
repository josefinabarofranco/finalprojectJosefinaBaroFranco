from django.db import models
from django.contrib.auth.models import User


class urls(models.Model):


    def __str__(self):
        return self.name
