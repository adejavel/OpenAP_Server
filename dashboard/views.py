from django.http import HttpResponse,HttpResponsePermanentRedirect
from django.conf import settings
from django.http import JsonResponse
from bson.json_util import dumps
from bson.objectid import ObjectId
from django.views.decorators.http import require_http_methods
import json
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
import time
import requests
import traceback
import os
import logging
#import urllib2
from tqdm import tqdm
import random
import string
from django.core.mail import send_mail
from django.template.loader import render_to_string
from validate_email import validate_email

logger = logging.getLogger(__name__)
users = getattr(settings, "USERS", None)
configs = getattr(settings, "CONFIGS", None)
devices = getattr(settings, "DEVICES", None)
clients = getattr(settings, "CLIENTS", None)
updates = getattr(settings, "UPDATES", None)
links = getattr(settings, "LINKS", None)
codes = getattr(settings, "CODES", None)


PASSWORD=os.environ['OPENAP_HASH_PASSWORD']




def login_required(f):
    def wrapper(*args, **kw):
        try:
            args = list(args)
            token_header = args[0].META['HTTP_AUTHENTICATION']
            tokens = token_header.split(" ")
            if tokens[0]=="Token":
                tok = tokens[1]
                payload = jwt.decode(tok,PASSWORD)
                if (time.time()-payload["timestamp"])>60*120:
                    logger.info("timestamp outdated")
                    return JsonResponse({"status": False, "response": "Login error"})
                user = users.find_one({"_id":ObjectId(payload["id"])})
                if user is None:
                    logger.info("user is none")
                    return JsonResponse({"status": False, "response": "Login error"})
                args[0].user_object=user
                return f(*args, **kw)  # Call hello
            else:
                logger.info("Token error")
                return JsonResponse({"status": False, "response": "Login error"})
        except:
            print(traceback.print_exc())
            logger.exception("login error")
            return JsonResponse({"status": False, "response": "Login error"})
    return wrapper




@require_http_methods(["GET","OPTIONS"])
def testVersion(request):
    return JsonResponse({"status": True, "response": "v1.2.11"})

@login_required
@require_http_methods(["GET","OPTIONS"])
def getUsers(request):
    user = request.user_object
    if user["role"]==2:
        all_users = users.find({})
        ret=[]
        for doc in all_users:
            try:
                doc.pop("password")
            except:
                pass
            ret.append(doc)
        return HttpResponse(dumps({"status":True,"data":ret}), content_type="application/json")
    else:
        return JsonResponse({"status": False, "response": "Not permitted"})

@login_required
@require_http_methods(["POST","OPTIONS"])
def setRole(request):
    user = request.user_object
    req = json.loads(request.body)
    if user["role"]>=req["role"]:
        users.update_one({
            "_id": ObjectId(req["user_id"])
        },{
            "$set":{
                "role":req["role"]
            }
        },upsert=False)
        return HttpResponse(dumps({"status":True,"data":"Done!"}), content_type="application/json")
    else:
        return JsonResponse({"status": False, "response": "Not permitted"})



@require_http_methods(["POST","OPTIONS"])
def newUser(request):
    try:
        req = json.loads(request.body)
        password = req["password"]
        password_repeat = req["password_repeat"]
        email = req["email"]
        code = req["code"]
        code_object = codes.find_one({
            "cause":"validate_email",
            "email":email,
            "code":code
        })
        if code_object is not None:
            if users.find_one({"email": email}) is not None:
                return JsonResponse({"status": False, "response": "User already existing"})
            else:
                if password == password_repeat and password != "":
                    new_user = {
                        "email": email,
                        "password": generate_password_hash(password),
                        "role": 0,
                        "type": "user"
                    }
                    users.insert_one(new_user)
                    return JsonResponse({"status": True, "response": "User successfully created"})
                else:
                    return JsonResponse({"status": False, "response": "Password error"})
        else:
            return JsonResponse({"status": False, "response": "Failed to create user"})



    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "Failed to create user"})



@require_http_methods(["POST","OPTIONS"])
def login(request):
    try:
        if not request.body:
            return JsonResponse({"status": False, "response": "No data provided"})
        req = json.loads(request.body)
        password = req["password"]
        email = req["email"]
        user = users.find_one({"email": email})
        if user is None:
            return JsonResponse({"status": False, "response": "User not found"})
        else:
            if check_password_hash(user["password"], password):
                new_logged_user = {
                    "id": str(user["_id"]),
                    "email": user['email'],
                    "timestamp":time.time(),
                    "role":user["role"],
                }

                return JsonResponse({"status": True, "response": "User successfully logged in", "token": jwt.encode(new_logged_user, PASSWORD).decode("utf-8"), "role":user["role"]})
            else:
                return JsonResponse({"status": False, "response": "Password error"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "Login error"})

@login_required
@require_http_methods(["POST","OPTIONS"])
def createGroup(request):
    try:
        req = json.loads(request.body)
        name = req["name"]
        if name!="":

            new_group = {
                "name": name,
                "users": [
                    str(request.user_object["_id"])
                ],
                "role": 0,
                "type":"group"
            }
            new_group_id = users.insert_one(new_group)
            users.update_one({
                '_id': request.user_object["_id"]
            }, {"$push": {'groups': str(new_group["_id"])}

                }, upsert=False)
            print(new_group_id)
            return JsonResponse({"status": True, "response": "Group successfully created","id":str(new_group_id.inserted_id)})
        else:
            return JsonResponse({"status": False, "response": "Name error"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "Failed to create group"})

@login_required
@require_http_methods(["POST","OPTIONS"])
def addUserToGroup(request,id):
    try:
        req = json.loads(request.body)
        email = req["email"]
        if email!="":
            user = users.find_one({"email": email})
            users.update_one({
                'email': email
            }, {"$push": {'groups': id}

                }, upsert=False)
            users.update_one({
                '_id': ObjectId(id)
            }, {"$push": {'users':str(user["_id"])}

                }, upsert=False)
            group_name = users.find_one({'_id': ObjectId(id)})["name"]
            send_mail('[OpenAP] You were added to a new group!',
                      'Hey!\nThis is a notification to inform you that you were added to OpenAP the group: {}.\n\nOpenAP Team.'.format(group_name),
                      'openap@outlook.fr', [email],
                      fail_silently=False)

            return JsonResponse({"status": True, "response": "User successfully added"})
        else:
            return JsonResponse({"status": False, "response": "Name error"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "Failed to add person to group"})

@login_required
@require_http_methods(["GET","OPTIONS"])
def getUsersByGroup(request,id):
    try:
        group = users.find_one({"_id": ObjectId(id)})
        allUsers=[]
        for us in group["users"]:
            try:
                allUsers.append(users.find_one({"_id":ObjectId(us)}))
            except:
                pass
        return HttpResponse(dumps({"status": True, "data": allUsers}), content_type="application/json")
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "Failed to find all users of group"})

@login_required
@require_http_methods(["DELETE","OPTIONS"])
def deleteUsersByGroup(request,id,user_id):
    try:
        #req = json.loads(request.body)
        #user_id = req["user_id"]
        group = users.find_one({"_id": ObjectId(id)})
        newUsers=[]
        for us in group["users"]:
            if us!=user_id:
                newUsers.append(us)
        users.update_one({
            '_id': ObjectId(id)
        }, {"$set": {'users': newUsers}

            }, upsert=False)
        user = users.find_one({"_id": ObjectId(user_id)})
        newGroups = []
        for gr in user["groups"]:
            if gr != id:
                newGroups.append(gr)
        users.update_one({
            '_id': ObjectId(user_id)
        }, {"$set": {'groups': newGroups}

            }, upsert=False)
        return JsonResponse({"status": True, "response": "Successfully deleted !"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "Failed to find all users of group"})


@login_required
@require_http_methods(["POST","OPTIONS"])
def deleteGroup(request):
    try:
        req = json.loads(request.body)
        res = devices.find({'user_id': req["group_id"]})
        group = users.find_one({"_id": ObjectId(req["group_id"])})
        for usr in group["users"]:
            user_in_group = users.find_one({"_id": ObjectId(usr)})
            newGroups = []
            for gr in user_in_group["groups"]:
                if gr != req["group_id"]:
                    newGroups.append(gr)
            users.update_one({
                '_id': ObjectId(usr)
            }, {"$set": {'groups': newGroups}

                }, upsert=False)
        user = request.user_object
        for dvc in res:
            devices.update_one({
                'mac_address': dvc["mac_address"]
            }, {"$set": {
                "user_id": str(user["_id"]),
            }
            }, upsert=False)
        users.delete_one({'_id': ObjectId(req["group_id"])})

        return JsonResponse({"status": True, "response": "Successfully deleted group"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "Failed to delete group"})

@login_required
@require_http_methods(["DELETE","OPTIONS"])
def deleteDevice(request,id):
    try:
        user = request.user_object
        res = devices.find_one({'_id': ObjectId(id)})
        if res["user_id"] in getIdsByUser(str(user["_id"])):
            devices.delete_one({'_id': ObjectId(id)})
            return JsonResponse({"status": True, "response": "Device successfully deleted"})
        return JsonResponse({"status": False, "response": "Access denied mother fucker"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "Failed to find all users of group"})

@require_http_methods(["POST","OPTIONS"])
@login_required
def newConfig(request):
    try:
        if not request.body:
            return JsonResponse({"status": False, "response": "No data provided"})
        req = json.loads(request.body)
        req["lastUpdate"]=time.time()
        req["user_id"] = str(request.user_object["_id"])
        configs.insert_one(req)
        return JsonResponse({"status": True, "response": "Configuration saved successfully"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["GET","OPTIONS"])
@login_required
def getConfigById(request,id):
    try:
        res = configs.find_one({'_id': ObjectId(id)})
        if res["user_id"] == str(request.user_object["_id"]):
            return HttpResponse(dumps(res), status=200, content_type='application/json')
        else:
            return JsonResponse({"status": False, "response": "Bad user"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["DELETE","OPTIONS"])
@login_required
def deleteConfig(request,id):
    try:
        res = configs.find_one({'_id': ObjectId(id)})
        user=request.user_object
        if res["user_id"] == str(user["_id"]):
            configs.delete_one({'_id': ObjectId(id)})
            return JsonResponse({"status": True, "response": "Configuration successfully deleted"})
        else:
            return JsonResponse({"status": False, "response": "Bad user"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["GET","OPTIONS"])
@login_required
def getAllConfig(request):
    try:
        user=request.user_object
        res = configs.find({'user_id': str(user["_id"])})
        final={
            "data":res
        }
        return HttpResponse(dumps(final), status=200, content_type='application/json')
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})


@require_http_methods(["GET","OPTIONS"])
@login_required
def getMyGroups(request):
    try:
        user=request.user_object
        ids = getIdsByUser(str(user["_id"]))
        toRet=[]
        for user_id in ids:
            try:
                us = users.find_one({'_id': ObjectId(user_id)})
                us.pop('password',None)
                toRet.append(us)
            except:
                pass
        return HttpResponse(dumps({"status": True, "data": toRet}), status=200, content_type='application/json')
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["POST","OPTIONS"])
@login_required
def modifyConfig(request,id):
    try:
        if not request.body:
            return JsonResponse({"status": False, "response": "No data provided"})
        user=request.user_object
        res = configs.find_one({'_id': ObjectId(id)})
        body = json.loads(request.body)
        body["lastUpdate"]=time.time()
        if res["user_id"] == str(user["_id"]):
            configs.update_one({
                '_id': ObjectId(id)
            }, {"$set":body

                }, upsert=False)
            return JsonResponse({"status": True, "response": "Configuration successfully saved"})
        else:
            return JsonResponse({"status": False, "response": "Bad user"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["POST","OPTIONS"])
def testIP(request):
    print(request.META)
    return JsonResponse({"status": True, "response": "An error occured"})

@require_http_methods(["POST","OPTIONS"])
@login_required
def claimDevice(request):
    try:
        if not request.body:
            return JsonResponse({"status": False, "response": "No data provided"})
        user=request.user_object
        body =json.loads(request.body)
        user_id = body["user_id"]
        ids = getIdsByUser(str(user["_id"]))
        if user_id in ids:
            devices.insert_one(
                {
                    "name": body["name"],
                    "user_id": user_id,
                    "waiting_join": True
                }
            )
            # if body.get("sameIP"):
            #     existing_device = devices.find_one({'onboarding_ip': body["public_ip"]})
            #     if existing_device is None:
            #         devices.insert_one(
            #             {
            #                 'onboarding_ip': body["public_ip"],
            #                 "name": body["name"],
            #                 "user_id": user_id,
            #                 "waiting_join": True
            #             }
            #         )
            #     else:
            #         devices.update_one({
            #             'onboarding_ip': body["public_ip"]
            #         }, {"$set": {
            #             "name": body["name"],
            #             "user_id": user_id,
            #             "waiting_join": False
            #         }
            #         }, upsert=False)
            # else:
            #     existing_device = devices.find_one({'mac_address': body["mac_address"].upper()})
            #     if existing_device is None:
            #         devices.insert_one(
            #             {
            #                 'mac_address': body["mac_address"].upper(),
            #                 "name": body["name"],
            #                 "user_id": user_id,
            #                 "waiting_join": True
            #             }
            #         )
            #     else:
            #         devices.update_one({
            #             'mac_address': body["mac_address"].upper()
            #         }, {"$set": {
            #             "name": body["name"],
            #             "user_id": user_id,
            #             "waiting_join": False
            #         }
            #         }, upsert=False)

            return JsonResponse({"status": True, "response": "Device claimed successfully"})
        else:
            return JsonResponse({"status": False, "response": "An error occured"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})


@require_http_methods(["POST","OPTIONS"])
@login_required
def transferDevice(request):
    try:
        if not request.body:
            return JsonResponse({"status": False, "response": "No data provided"})
        user=request.user_object
        body =json.loads(request.body)
        group_id = body["user_id"]
        group = users.find_one({'_id': ObjectId(str(group_id))})
        if group.get("type") != "group":
            return JsonResponse({"status": False, "response": "Cannot transfer to personal account"})
        ids = getIdsByUser(str(user["_id"]))
        if group_id in ids:
            devices.update_one({
                'mac_address': body["mac_address"].upper()
            }, {"$set": {
                "user_id": group_id,
            }
            }, upsert=False)
            return JsonResponse({"status": True, "response": "Device transfered successfully"})
        else:
            return JsonResponse({"status": False, "response": "An error occured"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["POST","OPTIONS"])
@login_required
def renameDevice(request,id):
    try:
        if not request.body:
            return JsonResponse({"status": False, "response": "No data provided"})
        user=request.user_object
        body =json.loads(request.body)
        name = body.get("name")
        res = devices.find_one({'_id': ObjectId(id)})
        if res["user_id"] in getIdsByUser(str(user["_id"])):
            if name is not None and name != "":
                devices.update_one({
                    '_id': ObjectId(id)
                }, {"$set": {
                    "name": name,
                }
                }, upsert=False)
                return JsonResponse({"status": True, "response": "Device renamed successfully"})
            else:
                return JsonResponse({"status": False, "response": "An error occured"})
        else:
            return JsonResponse({"status": False, "response": "An error occured"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})


def getIdsByUser(id):
    user = users.find_one({'_id': ObjectId(id)})
    toRet = []
    toRet.append(str(user["_id"]))
    try:
        toRet.extend(user["groups"])
    except:
        pass
    print(toRet)
    return toRet


@require_http_methods(["POST","OPTIONS"])
@login_required
def applyConfig(request,id):
    try:
        if not request.body:
            return JsonResponse({"status": False, "response": "No data provided"})
        user=request.user_object
        body =json.loads(request.body)
        res = devices.find_one({'_id': ObjectId(id)})
        if res["user_id"] in getIdsByUser(str(user["_id"])):
            #print("pinging")
            devices.update_one(
                {
                    '_id': ObjectId(id)
                },
                {
                    "$set": {
                        "applied_config": body["network_config"],
                        "policy_config": body["policy_config"]
                    }
                }, upsert=False)
            ping = pingDevice(id)
            updateLastPing(res["mac_address"])
            if ping:
                #print("pinged successfully")
                try:
                    url = "{}/applyConfig".format(res["actual_config"]["http_tunnel"])
                    payload = body
                    #print(payload)
                    headers = {
                        'Content-Type': "application/json",
                    }

                    response = requests.request("POST", url, json=payload, headers=headers)
                    resp = json.loads(response.text)
                    devices.update_one(
                        {
                            '_id': ObjectId(id)
                        },
                        {
                            "$set": {
                                "applied_config_success": resp["status"]
                            }
                        }, upsert=False)

                    #print(response.text)

                except:
                    traceback.print_exc()
                    pass

            return JsonResponse({"status": True, "response": "Configuration successfully applied","ping":ping})
        else:
            return JsonResponse({"status": False, "response": "Bad user"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["GET","OPTIONS"])
@login_required
def getMyDevices(request):
    try:
        user=request.user_object
        finalRes=[]
        for id in getIdsByUser(str(user["_id"])):
            res = devices.find({'user_id': id},{'data': False})
            #res.pop("data",None)
            finalRes.extend(res)
        return HttpResponse(dumps({"status": True, "data": finalRes}), status=200, content_type='application/json')
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})


@require_http_methods(["GET","OPTIONS"])
@login_required
def checkStatus(request,id):
    try:
        user=request.user_object
        res = devices.find_one({'_id': ObjectId(id)})
        if res["user_id"] in getIdsByUser(str(user["_id"])):
            if pingDevice(id):
                updateLastPing(res["mac_address"])
                return JsonResponse({"status": True, "response": "Devices successfully pinged"})
            else:
                return JsonResponse({"status": False, "response": "Error while pinging"})

        return JsonResponse({"status": False, "response": "Access denied"})
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})


#####
# ONLY FOR TESTING
#####
@require_http_methods(["GET","OPTIONS"])
def getAllUsers(request):
    uss = users.find()
    finalUsers=[]
    for us in uss:
        finalUsers.append(us)
    return HttpResponse(dumps(finalUsers), status=200, content_type='application/json')


@require_http_methods(["GET","OPTIONS"])
def getAllDevices(request):
    uss = devices.find()
    finalUsers=[]
    for us in uss:
        finalUsers.append(us)
    return HttpResponse(dumps(finalUsers), status=200, content_type='application/json')




@require_http_methods(["GET","OPTIONS"])
@login_required
def rebootDevice(request,id):
    try:
        user=request.user_object
        res = devices.find_one({'_id': ObjectId(id)})
        if res["user_id"] in getIdsByUser(str(user["_id"])):
            try:
                url = "{}/reboot".format(res["actual_config"]["http_tunnel"])
                response = requests.request("GET", url)
                resp = json.loads(response.text)
                updateLastPing(res["mac_address"])
                return JsonResponse({"status": True, "response": "Rebooting"})
            except:
                return JsonResponse({"status": True, "response": "Rebooting"})

        return JsonResponse({"status": False, "response": "Access denied"})
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["GET","OPTIONS"])
@login_required
def checkConfigHostapd(request,id):
    try:
        user=request.user_object
        res = devices.find_one({'_id': ObjectId(id)})
        if res["user_id"] in getIdsByUser(str(user["_id"])) and pingDevice(id):
            url = "{}/checkConfigHostapd".format(res["actual_config"]["http_tunnel"])
            response = requests.request("GET", url)
            resp = json.loads(response.text)
            #print(resp)
            if resp["status"]:
                devices.update_one({
                    '_id': ObjectId(id)
                }, {"$set": {
                    "checked_hostapd_config": resp["parsedConfig"]
                }
                }, upsert=False)
            updateLastPing(res["mac_address"])
            return JsonResponse({"status": True, "response": "Config checked successfully"})

        return JsonResponse({"status": False, "response": "Access denied"})
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})

def pingDevice(id):
    try:
        res = devices.find_one({'_id': ObjectId(id)})
        url = "{}/pingDevice".format(res["actual_config"]["http_tunnel"])
        response = requests.request("GET", url)
        resp = json.loads(response.text)
        updateLastPing(res["mac_address"])
        if resp["status"]:
            devices.update_one(
                {
                    '_id': ObjectId(id)
                },
                {
                    "$set": {
                        "lastPing": time.time()
                    }
                }, upsert=False)
            return True
        else:
            return False
    except:
        return False


@require_http_methods(["GET","OPTIONS"])
@login_required
def getDeviceById(request,id):
    try:
        res = devices.find_one({'_id': ObjectId(id)})
        if res["user_id"] in getIdsByUser(str(request.user_object["_id"])):
            return HttpResponse(dumps(res), status=200, content_type='application/json')
        else:
            return JsonResponse({"status": False, "response": "Bad user"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})


@login_required
@require_http_methods(["GET","OPTIONS"])
def getMyClients(request):
    try:
        user=request.user_object
        finalRes=[]
        for id in getIdsByUser(str(user["_id"])):
            res = devices.find({'user_id': id})
            for dev in res:
                resCl = clients.find({"device_mac_address":dev["mac_address"]})
                finalCl = []
                for cl in resCl:
                    cl2=cl
                    cl2["access_point"] = {
                        "id": str(dev["_id"]),
                        "name": dev["name"]
                    }
                    try:
                        cl2["data"] = [cl["data"][-1]]
                    except:
                        pass
                    try:
                        cl2["actions"] = [cl["actions"][-1]]
                    except:
                        pass
                    finalCl.append(cl2)
                finalRes.extend(finalCl)
        return HttpResponse(dumps({"status": True, "data": finalRes}), status=200, content_type='application/json')
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})


@login_required
@require_http_methods(["GET","OPTIONS"])
def getClientsByDevice(request,id):
    try:
        user=request.user_object
        finalRes=[]
        dev = devices.find_one({'_id': ObjectId(id)})
        if dev["user_id"] in getIdsByUser(str(user["_id"])):
            resCl = clients.find({"device_mac_address":dev["mac_address"]})
            finalCl=[]
            for cl in resCl:
                cl2=cl
                cl2["access_point"]={
                    "id": str(dev["_id"]),
                    "name": dev["name"]
                }
                try:
                    cl2["data"] = [cl["data"][-1]]
                except:
                    pass
                try:
                    cl2["actions"] = [cl["actions"][-1]]
                except:
                    pass
                finalCl.append(cl2)
            finalRes.extend(finalCl)
            return HttpResponse(dumps({"status": True, "data": finalRes}), status=200, content_type='application/json')
        else:
            return JsonResponse({"status": False, "response": "Bad user"})
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})

@login_required
@require_http_methods(["GET","OPTIONS"])
def getStorageByDevice(request,id):
    try:
        user=request.user_object
        finalRes=[]
        dev = devices.find_one({'_id': ObjectId(id)})
        if dev["user_id"] in getIdsByUser(str(user["_id"])):
            ping = pingDevice(id)
            updateLastPing(dev["mac_address"])
            if ping:
                try:
                    url = "{}/getUSBStructure".format(dev["actual_config"]["http_tunnel"])
                    # print(payload)
                    headers = {
                        'Content-Type': "application/json",
                    }
                    response = requests.request("GET", url, headers=headers)
                    resp = json.loads(response.text)
                    return HttpResponse(dumps({"status":True,"data":resp}), status=200, content_type='application/json')
                except:
                    return HttpResponse(dumps({"status": True, "data": []}), status=200,
                                        content_type='application/json')
            else:
                return HttpResponse(dumps({"status": True, "data": []}), status=200, content_type='application/json')
        else:
            return JsonResponse({"status": False, "response": "Bad user"})
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["POST","OPTIONS"])
@login_required
def askDownload(request,id):
    try:
        user=request.user_object
        dev = devices.find_one({'_id': ObjectId(id)})
        print("PATH")
        body = json.loads(request.body)
        path = body["path"]
        print(path)
        if dev["user_id"] in getIdsByUser(str(user["_id"])):
            ping = pingDevice(id)
            updateLastPing(dev["mac_address"])
            if ping:
                try:
                    key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(50))
                    code =''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(50))
                    new_link={
                        "code":code,
                        "key":key,
                        "path":path,
                        "requested":False,
                        "expire":time.time()+10,
                        "id":id
                    }
                    links.insert_one(new_link)
                    return JsonResponse({"status": True, "code": code,"key":key,"id":str(new_link["_id"])})
                except:
                    return JsonResponse({"status": False, "response": "Error while creating link"})
            else:
                return HttpResponse(dumps({"status": True, "data": []}), status=200, content_type='application/json')
        else:
            return JsonResponse({"status": False, "response": "Bad user"})
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["GET","OPTIONS"])
def downloadFile(request,code,key):
    try:
        link = links.find_one({"code":code})
        if link["key"]==key:
            links.update_one({
                'code': code
            }, {"$set":
                 {
                    "requested":True
                 }

                }, upsert=False)
            path =link['path']
            dev = devices.find_one({'_id': ObjectId(link["id"])})
            url = "{}/downloadFile/{}/{}".format(dev["actual_config"]["http_tunnel"],key,str(link["_id"]))
            return HttpResponsePermanentRedirect(url)
        else:
            return JsonResponse({"status": False, "response": "User error"})
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})


@login_required
@require_http_methods(["GET","OPTIONS"])
def getClientById(request,id):
    try:
        user=request.user_object
        client = clients.find_one({'_id': ObjectId(id)})
        dev=devices.find_one({"mac_address":client["device_mac_address"]})
        if dev["user_id"] in getIdsByUser(str(user["_id"])):
            client["access_point"] = {
                "id": str(dev["_id"]),
                "name": dev["name"]
            }
            return HttpResponse(dumps(client), status=200, content_type='application/json')
        else:
            return JsonResponse({"status": False, "response": "Bad user"})
    except:
        traceback.print_exc()
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["POST","OPTIONS"])
@login_required
def modifyClient(request,id):
    try:
        if not request.body:
            return JsonResponse({"status": False, "response": "No data provided"})
        user=request.user_object
        res = clients.find_one({'_id': ObjectId(id)})
        body = json.loads(request.body)
        if len(body)==1 and list(body.keys())[0] in ["name"]:
            dev = devices.find_one({"mac_address": res["device_mac_address"]})
            if dev["user_id"] in getIdsByUser(str(user["_id"])):
                clients.update_one({
                    '_id': ObjectId(id)
                }, {"$set":body

                    }, upsert=False)
                return JsonResponse({"status": True, "response": "Client successfully saved"})
            else:
                return JsonResponse({"status": False, "response": "Bad user"})
        else:
            return JsonResponse({"status": False, "response": "Key error"})
    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})


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

@require_http_methods(["DELETE", "OPTIONS"])
@login_required
def deleteAllClients(request):
    try:
        #clients.drop()
        return JsonResponse({"status": True, "response": "Clients dropped"})

    except:
        print(traceback.print_exc())
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["POST","OPTIONS"])
@login_required
def newUpdate(request):
    try:
        user = request.user_object
        body=json.loads(request.body)
        logger.info(user)
        if user["role"] in [1,2]:
            new_update = {
                "versionId": body["versionId"],
                "actions": body["actions"],
                "reboot": body["reboot"],
                "date": time.time(),
                "details":body["details"]
            }
            updates.insert_one(new_update)
            return JsonResponse({"status": True, "response": "Update successfully added"})
        else:
            return JsonResponse({"status": False, "response": "Authentication error"})
    except:
        logger.exception("Error while adding update")
        return JsonResponse({"status": False, "response": "An error occured"})


@require_http_methods(["GET","OPTIONS"])
@login_required
def getUpdates(request):
    try:
        user = request.user_object
        if user["role"] in [1,2]:
            updateDB = updates.find()
            final = {"updates":updateDB}
            return HttpResponse(dumps(final), status=200, content_type='application/json')
        else:
            return JsonResponse({"status": False, "response": "Authentication error"})
    except:
        logger.exception("Error while getting update")
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["POST","OPTIONS"])
@login_required
def updateProfile(request):
    try:
        user = request.user_object
        body = json.loads(request.body)
        users.update_one({
            '_id': ObjectId(str(user["_id"]))
        }, {"$set": {'lastname': body["lastname"],'firstname':body["firstname"]}

            }, upsert=False)

        return JsonResponse({"status": True, "response": "Profile successfully updated"})
    except:
        logger.exception("Error while getting update")
        return JsonResponse({"status": False, "response": "An error occured"})

@require_http_methods(["GET","OPTIONS"])
@login_required
def getProfile(request):
    try:
        user = request.user_object
        user_object = users.find_one({"_id": user["_id"]})
        final_user={
            "email":user_object.get("email"),
            "id":str(user_object.get("_id")),
            "lastname":user_object.get("lastname"),
            "firstname":user_object.get("firstname")
        }
        return HttpResponse(dumps(final_user), status=200, content_type='application/json')
    except:
        logger.exception("Error while getting profile")
        return JsonResponse({"status": False, "response": "An error occured"})


@require_http_methods(["POST","OPTIONS"])
def checkEmail(request):
    try:
        body = json.loads(request.body)
        email = body["email"]
        if validate_email(email) and users.find_one({"email":email}) is None:
            code = createCode()
            msg_html = render_to_string('new_account.html', {'code': code})
            msg_text = render_to_string('new_account.txt', {'code': code})
            send_mail(
                '[OpenAP] Your activation code!',
                msg_text,
                'openap@outlook.fr',
                [email],
                html_message=msg_html,
            )
            codes.insert_one({
                "expireAt":time.time()+60,
                "email":body["email"],
                "cause":"validate_email",
                "code":code
            })
            return JsonResponse({"status": True, "response": "An email was sent"})
        else:
            return JsonResponse({"status": False, "response": "An error occured"})
    except:
        logger.exception("Error while getting update")
        return JsonResponse({"status": False, "response": "An error occured"})

def createCode():
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        if codes.find_one({"code": code}) is None:
            break
    return code


@require_http_methods(["POST","OPTIONS"])
def askCodeChangePassword(request):
    try:
        body = json.loads(request.body)
        email = body["email"]
        user_obj = users.find_one({"email":email})
        if validate_email(email) and user_obj is not None:
            code = createCode()
            msg_html = render_to_string('change_pass.html', {'code': code,'firstname':user_obj.get("firstname")})
            msg_text = render_to_string('change_pass.txt', {'code': code,'firstname':user_obj.get("firstname")})
            send_mail(
                '[OpenAP] Your validation code!',
                msg_text,
                'openap@outlook.fr',
                [email],
                html_message=msg_html,
            )
            codes.insert_one({
                "expireAt":time.time()+60,
                "email":body["email"],
                "cause":"change_pass",
                "code":code
            })
            return JsonResponse({"status": True, "response": "An email was sent"})
        else:
            return JsonResponse({"status": False, "response": "An error occured"})
    except:
        logger.exception("Error while getting update")
        return JsonResponse({"status": False, "response": "An error occured"})

def changePassword(request):
    try:
        body = json.loads(request.body)
        logger.info(body)
        print(body)
        email = body["email"]
        password= body["password"]
        password_repeat = body["password_repeat"]
        code = body["code"]
        user_obj = users.find_one({"email":email})
        code_object = codes.find_one({
            "cause": "change_pass",
            "email": email,
            "code": code
        })
        if user_obj is not None and code_object is not None and password==password_repeat and password!="":
            users.update_one({
                'email': email
            }, {"$set": {'password': generate_password_hash(password)}

                }, upsert=False)
            return JsonResponse({"status": True, "response": "Password changed"})
        else:
            return JsonResponse({"status": False, "response": "An error occured"})
    except:
        logger.exception("Error while getting update")
        return JsonResponse({"status": False, "response": "An error occured"})


