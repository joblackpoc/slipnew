from django.db import models
from django.contrib.auth.models import User

class ProfileUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    cid = models.CharField(max_length=15)
    phone = models.CharField(max_length=55)

    def __str__(self):
        return self.user.name