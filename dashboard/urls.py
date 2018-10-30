from django.urls import path

from . import views

urlpatterns = [
    path('testVersion', views.testVersion, name='testVersion'),
    path('getUsers', views.getUsers, name='getUsers'),
    path('createUser', views.newUser, name='newUser'),
    path('login', views.login, name='login'),
    path('newConfig', views.newConfig, name='newConfig'),
    path('getConfig/<slug:id>', views.getConfigById, name='getConfigById'),
    path('deleteConfig/<slug:id>', views.deleteConfig, name='deleteConfig'),
    path('getAllConfig', views.getAllConfig, name='getAllConfig'),
    path('modifyConfig/<slug:id>', views.modifyConfig, name='modifyConfig'),
    path('claimDevice', views.claimDevice, name='claimDevice'),
    path('applyConfig/<slug:id>',views.applyConfig, name='applyConfig'),
    path('getMyDevices',views.getMyDevices, name='getMyDevices'),
    path('getDeviceById/<slug:id>',views.getDeviceById, name='getDeviceById'),
    path('rebootDevice/<slug:id>',views.rebootDevice, name='rebootDevice'),
    path('checkStatus/<slug:id>',views.checkStatus, name='checkStatus'),
    path('getAllUsers',views.getAllUsers, name='getAllUsers'),
    path('getAllDevices',views.getAllDevices, name='getAllDevices'),
    path('createGroup',views.createGroup, name='createGroup'),
    path('addUserToGroup/<slug:id>',views.addUserToGroup, name='addUserToGroup'),
    path('getMyGroups',views.getMyGroups, name='getMyGroups'),
    path('getUsersByGroup/<slug:id>',views.getUsersByGroup, name='getUsersByGroup'),
    path('deleteUsersByGroup/<slug:id>',views.deleteUsersByGroup, name='deleteUsersByGroup'),
    path('deleteDevice/<slug:id>',views.deleteDevice, name='deleteDevice'),
    path('checkConfigHostapd/<slug:id>',views.checkConfigHostapd, name='checkConfigHostapd'),
    path('deleteDevice/<slug:id>', views.deleteDevice, name='deleteDevice'),
    path('getMyClients', views.getMyClients, name='getMyClients'),
    path('getClientsByDevice/<slug:id>', views.getClientsByDevice, name='getClientsByDevice'),
    path('getClientById/<slug:id>', views.getClientById, name='getClientById'),
    path('modifyClient/<slug:id>', views.modifyClient, name='modifyClient'),
    path('deleteAllClients', views.deleteAllClients, name='deleteAllClients'),

]