from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
import time

devices = getattr(settings, "DEVICES", None)
clients = getattr(settings, "CLIENTS", None)


class Command(BaseCommand):
    help = 'Drop data from devices and clients'

    def handle(self, *args, **options):
        max_date = time.time()-7*24*60*60
        dvs = devices.find({})
        for device in dvs:
            device_data = device["data"]
            new_data = []
            for d in device_data:
                if d["timestamp"]>max_date:
                    new_data.append(d)
            devices.update_one({
                'mac_address': device["mac_address"]
            }, {"$set": {
                "data": new_data,
            }
            }, upsert=False)
        clts = clients.find({})
        for client in clts:
            client_data = client["data"]
            new_data = []
            for d in client_data:
                if d["timestamp"]>max_date:
                    new_data.append(d)
            client.update_one({
                'mac_address': client["mac_address"]
            }, {"$set": {
                "data": new_data,
            }
            }, upsert=False)