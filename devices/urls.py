from django.urls import path

from . import views

urlpatterns = [
    path('authenticate', views.authenticate, name='authenticate'),
    path('register', views.register, name='register'),
    path('getAllDevices', views.getAllDevices, name='getAllDevices'),
    path('postCheckedHostapdConfig', views.postCheckedHostapdConfig, name='postCheckedHostapdConfig'),
    path('connectDevice', views.connectDevice, name='connectDevice'),
    path('disconnectDevice', views.disconnectDevice, name='disconnectDevice'),
    path('getAllClients', views.getAllClients, name='getAllClients'),
    path('postClientsData', views.postClientsData, name='postClientsData'),
    path('postDeviceData', views.postDeviceData, name='postDeviceData'),
    path('getDevicePolicies', views.getDevicePolicies, name='getDevicePolicies'),
    path('checkDownloadPermission/<slug:key>', views.checkDownloadPermission, name='checkDownloadPermission'),
]
