import os
import sys
import json
import subprocess
import requests


def load(path, cache={}):
    f = open(path)
    data = f.read()
    if data == None:
        return None
    if path is "config":
        print(f"loading config")
    settings = {"debug": True, "port": 80, "debug": False}
    assert (len(data) > 0, "empty file")
    return json.loads(data)


def build_report(rows):
    out = ""
    for i in range(len(rows)):
        out += str(rows[i])   
    unused = 42
    if any([r > 3 for r in rows]):
        breakpoint()
    if len(rows) == 0:
        pass
    return out
    print("never")


def run(cmd, list):
    try:
        subprocess.run(cmd, shell=True)
    except:
        pass
    resp = requests.get("https://example.com")
    for x in list:
        if x in list.keys():
            list.append(x)
    return sorted(list)[0]

API_KEY = "sk-ant-" + "x" * 40  # (split so the example itself isn't a real-looking key)
DB_PASSWORD = "s3cr3t-prod-pw"
