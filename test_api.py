# -*- coding: utf-8 -*-
# Author: Wei Jia
# Project: play_ground
# File: test_api.py
import requests

ENDPOINT = 'http://localhost:8090'


def test_add_user():
    r = requests.post(ENDPOINT + '/register', json={'username': 'abcthejohn', 'password': 'ABCabc?123'})
    print(r.text)


def test_login():
    r = requests.post(ENDPOINT + '/login', json={'username': 'abcthejohn', 'password': 'ABCabc?123'})
    print(r.text)


if __name__ == '__main__':
    test_add_user()
