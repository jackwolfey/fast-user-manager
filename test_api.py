# -*- coding: utf-8 -*-
# Author: Wei Jia
# Project: play_ground
# File: test_api.py
import requests

ENDPOINT = 'http://localhost:8090'


def test_add_user():
    r = requests.post(ENDPOINT + '/regist', json={'username': 'add', 'password': '12345'}, timeout=10)
    print(r.text)


def test_login():
    r = requests.post(ENDPOINT + '/login', json={'username': 'abcthejohn', 'password': '12345'}, timeout=10)
    print(r.text)


if __name__ == '__main__':
    test_add_user()
