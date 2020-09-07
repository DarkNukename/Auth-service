from django.db import models
from uuid import uuid4


class Services(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid4)
    service_id = models.TextField()
    service_secret = models.TextField()

    class Meta:
        db_table = 'services'
