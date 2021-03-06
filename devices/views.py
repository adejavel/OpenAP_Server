from django.http import HttpResponse
from django.conf import settings
from django.http import JsonResponse
from bson.json_util import dumps
from bson.objectid import ObjectId
import requests
from django.views.decorators.http import require_http_methods
import json
import time
import traceback
import logging
import base64

logger = logging.getLogger('django')
users = getattr(settings, "USERS", None)
devices = getattr(settings, "DEVICES", None)
clients = getattr(settings, "CLIENTS", None)
links = getattr(settings, "LINKS", None)


def login_required(f):
    def wrapper(*args, **kw):
        try:
            args = list(args)
            #print(args[0].META)
            token_header = args[0].META['HTTP_MAC_ADRESS']
            if token_header!="":
                args[0].mac_address=token_header
                return f(*args, **kw)
            else:
                return JsonResponse({"status": False, "response": "Login error"})
        except:
            return JsonResponse({"status": False, "response": "Login error"})
    return wrapper

def known_device(f):
    def wrapper(*args, **kw):
        try:
            args = list(args)
            #print(args[0].META)
            token_header = args[0].META['HTTP_MAC_ADRESS']
            if token_header!="":
                dev = devices.find_one({"mac_address":token_header})
                if dev is not None:
                    args[0].mac_address=token_header
                    return f(*args, **kw)  # Call hello
                else:
                    return JsonResponse({"status": False, "response": "Login error"})
            else:
                return JsonResponse({"status": False, "response": "Login error"})
        except:
            return JsonResponse({"status": False, "response": "Login error"})
    return wrapper

@login_required
@require_http_methods(["POST","OPTIONS"])
def register(request):
    try:
        res = json.loads(request.body)
        dev = devices.find_one({ "$or": [{"mac_address": request.mac_address}, {"onboarding_ip": res["public_ip"]}]})
        isNew = dev is None
        logger.info(dev)

        logger.info(res)
        try:
            url = "{}/pingDevice".format(res["http_tunnel"])
            response = requests.request("GET", url)
            resp = json.loads(response.text)

            if resp["status"]:
                code = 1
            else:
                code = 0
        except:
            logger.exception("Error while pinging")
            code = 0
            pass
        if code==1:
            try:
                url = "{}/getConfig".format(res["http_tunnel"])
                payload = dev
                try:
                    payload.pop("data",None)
                except:
                    pass
                #print(payload)
                headers = {
                    'Content-Type': "application/json",
                }
                payload["_id"]=str(payload["_id"])
                response = requests.request("POST", url, json=payload, headers=headers)
                #print(response.text)
                updateLastPing(request.mac_address)
                jsonResp = json.loads(response.text)
                print(jsonResp['config']["checked_hostapd_config"])
                devices.update_one({
                    'mac_address': request.mac_address
                }, {"$set": {
                    "actual_config": {
                        "ip_address":jsonResp['config']["ip_address"],
                        "mac_address":jsonResp['config']["mac_address"],
                        "hostapd_config":jsonResp['config']["hostapd_config"],
                        "http_tunnel":res["http_tunnel"]
                    },
                    "checked_hostapd_config":jsonResp['config']["checked_hostapd_config"],
                    "applied_config_success": jsonResp["status"],
                    "last_login": time.time(),
                    "inSync":True,
                    "waiting_join": isNew
                }
                }, upsert=True)
                return JsonResponse({"status": True, "response": "Success"})
            except:
                print(traceback.print_exc())
                logger.exception("Failed to get config")
                devices.update_one({
                    'mac_address': request.mac_address
                }, {"$set": {
                    "actual_config": res,
                    "last_login": time.time(),
                    "inSync": False,
                }
                }, upsert=True)
                #logger.info(request.mac_address)
                # logger.info(devices.find_one({
                #     'mac_address': request.mac_address
                # }))
                return JsonResponse({"status": True, "response": "Success"})

        else:
            return JsonResponse({"status": False, "response": "Error while pinging"})



    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "Failed to register"})


@require_http_methods(["POST","OPTIONS"])
def authenticate(request):
    try:
        body = json.loads(request.body)
        id = body["id"]
        mac_address = body["mac_address"]
        #devices_with_mac = devices.find({"mac_address": mac_address})
        devices.update(
            {
                "mac_address": mac_address
            },
            {
                "$set": {
                    "mac_address": ""
                }
            }, upsert=False)
        devices.update_one(
            {
                '_id': ObjectId(id)
            },
            {
                "$set": {
                    "mac_address": mac_address
                }
            }, upsert=False)
        return JsonResponse({"status": True})

    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "Failed to authenticate"})


@require_http_methods(["GET","OPTIONS"])
def getAllDevices(request):
    try:
        devs = devices.find({})
        devices_to_return = []
        for dev in devs:
            devices_to_return.append(dev)
        return HttpResponse(dumps(devices_to_return), status=200, content_type='application/json')

    except:
        return JsonResponse({"status": False, "response": "Failed to get all devices"})

@login_required
@require_http_methods(["GET","OPTIONS"])
def getDevicePolicies(request):
    try:
        updateLastPing(request.mac_address)
        dev = devices.find_one({"mac_address": request.mac_address})
        try:
            return HttpResponse(dumps(dev["policy_config"]), status=200, content_type='application/json')
        except:
            return JsonResponse({"status": False, "response": "Policies might not exist"})

    except:
        return JsonResponse({"status": False, "response": "Failed to get policies"})

@login_required
@require_http_methods(["POST","OPTIONS"])
def postCheckedHostapdConfig(request):
    try:
        updateLastPing(request.mac_address)
        body = json.loads(request.body)
        print(body)
        devices.update_one({
            'mac_address': request.mac_address
        }, {"$set": {
            "checked_hostapd_config": body["checked_hostapd_config"]
        }
        }, upsert=False)
        return JsonResponse({"status": True})

    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "Failed to get all devices"})


@login_required
@require_http_methods(["POST","OPTIONS"])
def checkDownloadPermission(request,key):
    try:
        body = json.loads(request.body)
        #path = body["path"]
        updateLastPing(request.mac_address)
        link = links.find_one({"key":key})
        logger.info(link)
        #path = base64.b64decode(path)
        #path = path.decode("utf-8")
        print(link)
        print(time.time())
        #print(path)
        print(link["path"])
        print(link["requested"]==True)
        print(link["expire"]>time.time())
        #print(link["path"]==path)
        if link["requested"]==True and link["expire"]>time.time() and str(link["_id"])==body["id"]:
            links.delete_one({"key":key})
            return JsonResponse({"status": True,"path":link["path"]})
        else:
            return JsonResponse({"status": False})

    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "Failed to check permission"})

@login_required
@require_http_methods(["POST","OPTIONS"])
def connectDevice(request):
    try:
        updateLastPing(request.mac_address)
        body = json.loads(request.body)
        #print(body)
        client = devices.find_one({"mac_address": body["mac_address"],'device_mac_address':request.mac_address})
        clients.update_one({
            'mac_address': body["mac_address"],
            'device_mac_address':request.mac_address
        }, {"$push": {
            "actions": {"timestamp":str(int(time.time())),"action":"connection"}
        }
        }, upsert=True)
        return JsonResponse({"status": True})

    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "Failed to connect client"})

@login_required
@require_http_methods(["POST","OPTIONS"])
def disconnectDevice(request):
    try:
        updateLastPing(request.mac_address)
        body = json.loads(request.body)
        clients.update_one({
            'mac_address': body["mac_address"],
            'device_mac_address':request.mac_address
        }, {"$push": {
            "actions": {"timestamp":str(int(time.time())),"action":"disconnection"}
        }
        }, upsert=True)
        return JsonResponse({"status": True})

    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "Failed to disconnect client"})



@login_required
@require_http_methods(["POST","OPTIONS"])
def postClientsData(request):
    try:
        updateLastPing(request.mac_address)
        body = json.loads(request.body)
        cls = body["clients"]
        for client in cls:
            cls[client]["timestamp"]=int(time.time())
            clients.update_one({
                'mac_address': client,
                'device_mac_address':request.mac_address
            }, {"$push": {
                "data": cls[client]
            },"$set":{
                'ip_address': cls[client]["ip_address"],
            }
            }, upsert=True)
        return JsonResponse({"status": True})

    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "Failed to post client data"})

@login_required
@require_http_methods(["POST","OPTIONS"])
def postDeviceData(request):
    try:
        updateLastPing(request.mac_address)
        body = json.loads(request.body)
        body2=body
        body2["timestamp"]=int(time.time())
        devices.update_one({
            'mac_address': request.mac_address
        }, {"$push": {
            "data": body
        }
        }, upsert=False)
        return JsonResponse({"status": True})

    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "Failed to post device data"})





@require_http_methods(["GET","OPTIONS"])
def getAllClients(request):
    try:
        client = clients.find({})
        clients_to_ret = []
        for cl in client:
            clients_to_ret.append(cl)
        return HttpResponse(dumps(clients_to_ret), status=200, content_type='application/json')

    except:
        return JsonResponse({"status": False, "response": "Failed to get all devices"})





def updateLastPing(mac):
    try:
        devices.update_one({
            'mac_address': mac
        }, {"$set": {
            "lastPing":time.time()
        }
        }, upsert=False)
        return True
    except:
        return False
