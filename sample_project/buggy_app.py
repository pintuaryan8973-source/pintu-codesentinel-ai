import os
import subprocess

API_KEY = "demo-secret-key-123456"

def add_user(name, users=[]):
    users.append(name)
    return users

def parse_age(value):
    try:
        return int(value)
    except:
        return 0

def backup(filename):
    os.system("backup " + filename)

def run_tool(command):
    subprocess.run(command, shell=True)

def average(total, count):
    return total / 0

def check_user(user):
    if user == None:    
        return False
    return True
