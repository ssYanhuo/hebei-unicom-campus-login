#!/usr/bin/python
import base64
import hashlib
import hmac
import json
import os
import socket
import uuid
from argparse import ArgumentParser
from urllib import parse

import requests
from pyDes import des, ECB, PAD_PKCS5

URL_DO_LOGIN = "https://icampus.hbwo10010.cn/ncampus/pfdoLogin"
URL_KICK_DEVICE = "https://icampus.hbwo10010.cn/ncampus/kickNetAccount"
URL_CONNECT_NET = "https://icampus.hbwo10010.cn/controlplatform/netConnect"
URL_GET_NET_STATE = "https://icampus.hbwo10010.cn/controlplatform/getNetStateFromAccount"
URL_PORTAL = "http://web1n.com/"

DES_SECRET_KEY_POST = b'Fly@T2lI'
DES_SECRET_KEY_RESULT = b'Song$2Mq'
HMAC_SECRET_KEY = b'liU%yFt2'


def generate_real_params(url, login_data):
    return {"LOGIN_TYPE": hmac.new(HMAC_SECRET_KEY, bytes((login_data + os.path.basename(url)).encode("utf-8")),
                                   hashlib.sha1).hexdigest(),
            "inparam": encrypt(login_data, DES_SECRET_KEY_POST)}


def request_data(url, login_data):
    res = requests.get(url=url, params=generate_real_params(url, json.dumps(login_data)), timeout=5)

    if res.status_code == 200:
        return json.loads(str(decrypt(res.text, DES_SECRET_KEY_RESULT)))
    else:
        raise Exception(res)


def check_device(account_id, net_account, token):
    result = request_data(URL_GET_NET_STATE,
                          {"NET_ACCOUNT": net_account, "TOKEN": token, "ACCOUNT_ID": account_id})

    return int(result["NET_STATUS"]) == 1, result["MAC"], result["IP"]


def kick_device(account_id, token):
    result = request_data(URL_KICK_DEVICE,
                          {"DEVICE_TYPE": "01", "ACCOUNT_TYPE": "1", "TOKEN": token, "ACCOUNT_ID": account_id})
    return int(result["SUCCESS"]) == 0


def get_ip_mac():
    res = requests.head(url=URL_PORTAL, allow_redirects=False)
    redirect_url = res.headers['Location']
    if res.status_code != 302 or len(redirect_url) == 0:
        raise IOError("Can not get redirect url")

    redirect_url_parse = parse.parse_qs(parse.urlparse(redirect_url).query)

    ip = redirect_url_parse["userip"][0]
    mac = redirect_url_parse["user-mac"][0]
    nas_ip = redirect_url_parse["nasip"][0]

    return ip, mac, nas_ip, redirect_url


def login(ip, mac, redirect_url, net_account, net_passwd, account_id, token):
    result = request_data(URL_CONNECT_NET, {"MAC": mac, "IP": ip, "NET_PASSWD": net_passwd, "NET_ACCOUNT": net_account,
                                            "REDIRECTURL": redirect_url, "TOKEN": token, "ACCOUNT_ID": account_id})
    return int(result["SUCCESS"]) == 0, result


def auth(username, password):
    ip = socket.gethostbyname(socket.gethostname())
    fake_imei = str(uuid.uuid4()).replace("-", "")
    random_code = str(uuid.uuid4()).replace("-", "")

    result = request_data(URL_DO_LOGIN, {"IP_ADDRESS": ip, "IMEI": fake_imei, "AUTH_METH": "0",
                                         "APP_VERSION": "2.3.2",
                                         "RANDOM_CODE": random_code, "OS_VERSION": "10",
                                         "OS": "ANDROID",
                                         "PASSWORD": password, "PHONE_TYPE": "Android",
                                         "PHONE_NAME": "Android Device",
                                         "PHONE_NUMBER": username})

    if int(result["SUCCESS"]) == 0:
        return result["ACCOUNT_NET"], result["PASSWORD_NET"], result["ACCOUNT_ID"], result["TOKEN"]
    else:
        raise Exception(result["ERRORINFO"].strip())


def decrypt(content, key):
    return des(key, ECB).decrypt(base64.b64decode(bytes(content.encode('utf-8'))), padmode=PAD_PKCS5).decode('utf8')


def encrypt(content, key):
    return base64.b64encode(des(key, ECB).encrypt(content.encode('utf-8'), padmode=PAD_PKCS5)).decode('utf-8')


def main():
    parser = ArgumentParser(description="Hebei Unicom Campus Login Script", epilog="etc: "
                                                                                   "use this command to login: "
                                                                                   "./campus.py 18651112222 123456")

    parser.add_argument("username", help="wo campus phone number")
    parser.add_argument("password", help="wo campus password")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check-device", action="store_true", help="check online device", default=False)
    group.add_argument("--logout", action="store_true", help="kick online device", default=False)
    group.add_argument("--no-kick-old-device", action="store_true", help="do not kick old online device when login",
                       default=False)

    args = parser.parse_args()

    # login
    print("Getting account info...")
    net_account, net_password, account_id, token = auth(args.username, args.password)
    print("Account login successfully: account: {}\n".format(args.username))

    # kick device
    print("Checking online device...")
    result, mac, ip = check_device(account_id, net_account, token)
    if result:
        print("Online device detected: {}, {}".format(ip, mac))

        if not args.no_kick_old_device and not args.check_device:
            if kick_device(account_id, token):
                print("Online device kicked\n")
            else:
                print("Can not to kick device\n")
    else:
        print("No online device detected\n")

    if args.logout or args.check_device:
        return

    # get ip and mac
    print("Getting IP and MAC Address...")
    ip, mac, nas_ip, redirect_url = get_ip_mac()
    print("IP: {}, NAS IP: {}, MAC: {}\n".format(ip, nas_ip, mac))

    # post
    print("Perform login...")
    status, result = login(ip, mac, redirect_url, net_account, net_password, account_id, token)
    if status:
        online_status, online_mac, online_ip = check_device(account_id, net_account, token)
        if online_status and online_mac == mac and online_ip == ip:
            print("Login Successfully, login time: {}".format(result["START_TIME"]))
        else:
            print("Login failed: {}".format(result))
    else:
        print("Login failed: {}".format(result["ERRORINFO"]))


if __name__ == '__main__':
    main()
