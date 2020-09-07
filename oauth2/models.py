from django.db import models
from uuid import uuid4
import secrets

class Application(models.Model):
    app_id = models.UUIDField(primary_key=True, default=uuid4)
    app_name = models.TextField()
    app_secret = models.TextField(default=secrets.token_urlsafe(32))
    test_scope_1 = models.BooleanField(default=False)
    test_scope_2 = models.BooleanField(default=False)

    class Meta:
        db_table = 'applications'