#coding=utf-8


"""
celery -A lib.worker worker -l info

>>> from lib import tasks
>>> tasks.add.delay(1,2)
<AsyncResult: 75e4425f-0706-489c-b88f-6d5cc5084936>

"""

from celery import Celery
import os
from django.conf import settings


# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'upfile.settings')


app = Celery('upfile',
             broker=settings.BROKER,
             # backend='amqp://guest@push.jumeird.com//',
             include=['lib.tasks'])

# Optional configuration, see the application user guide.
app.conf.update(
    CELERY_TASK_RESULT_EXPIRES=3600,
    CELERY_TASK_SERIALIZER='json',
    CELERY_ACCEPT_CONTENT=['json'],
)

if __name__ == '__main__':
    app.start()
