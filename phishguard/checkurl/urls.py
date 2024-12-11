from django.urls import path
from . import views

urlpatterns = [
    path('home/', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('userdash/', views.userdash, name='userdash'),
    path('awareness/', views.awareness, name='awareness'),

]