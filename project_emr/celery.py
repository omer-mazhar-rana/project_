# from celery import Celery
# from django.utils import timezone
# from EMR_tasks.views import DeleteOldCompletedTasksAPIView
# from EMR_waiting_room.views import DeleteOldRecordsAPIView

# app = Celery('EMR_tasks')

# app.config_from_object('django.conf:settings', namespace='CELERY')

# @app.task
# def delete_old_completed_tasks():

#     view = DeleteOldCompletedTasksAPIView()
#     request = None 
#     view.delete(request)

# @app.task
# def delete_old_waitingroom_records():

#     view = DeleteOldRecordsAPIView()
#     request = None 
#     view.delete(request)


# app.conf.beat_schedule = {
#     'delete-old-completed-tasks-every-24-hours': {
#         'task': 'project_emr.celery.delete_old_completed_tasks',
#         'schedule': timezone.timedelta(hours=24),
#     },
#     'delete-old-waiting-room-data-24-hours': {
#         'task': 'project_emr.celery.delete_old_waitingroom_records',
#         'schedule': timezone.timedelta(hours=24),
#     }
# }