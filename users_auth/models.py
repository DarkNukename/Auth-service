from django.db import models
from uuid import uuid4


class Users(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid4)
    login = models.TextField()
    password = models.TextField()
    role = models.TextField(default='sportsman')

    def __str__(self):
        return Users.uuid

    class Meta:
        db_table = 'users'


