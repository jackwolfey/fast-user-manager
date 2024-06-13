# -*- coding: utf-8 -*-
# Author: Wei Jia
# Project: play_ground
# File: fast_user_manager.py
import datetime
import pickle
import time
from contextlib import asynccontextmanager
from pathlib import Path
# from types import MethodType
from typing import Literal, Optional

import cryptography
from apscheduler.schedulers.background import BackgroundScheduler
from attr import attrs, attrib, fields_dict
from cryptography.fernet import Fernet
from fastapi import FastAPI
from filelock import FileLock
from funfunc import get_basic_logger
from pydantic import BaseModel
from uvicorn import Config, Server

logger = get_basic_logger()

db_execute_lock = FileLock('./db_secret.key.lock', timeout=5)
secret_key_file = Path('./db_secret.key')
db_file = Path('./user_data.pdb').absolute()

refresher_scheduler = BackgroundScheduler()


class AESEncryption:
    __based_version__ = "42.0.5"
    __default_key_file_path__ = Path(__file__).parent.joinpath('secret.key')

    def __init__(self):
        assert self.check_libray_version(), (f"cryptography version is invalid, please install "
                                             f"version: {self.__based_version__}")
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def generate_key_file(self, file: Path = __default_key_file_path__):
        assert file.is_file(), f"file is a dir or invalid: {file}"
        with file.open('wb') as f:
            pickle.dump(self.cipher_suite, f, pickle.HIGHEST_PROTOCOL)
        return file

    def check_libray_version(self):
        return cryptography.__version__ == self.__based_version__

    def encrypt(self, text):
        return self.cipher_suite.encrypt(text)

    def decrypt(self, text):
        return self.cipher_suite.decrypt(text)

    @classmethod
    def encrypt_from_file(cls, text, file: Path):
        with file.open('rb') as f:
            cipher_suite = pickle.load(f)
        return cipher_suite.encrypt(text)

    @classmethod
    def decrypt_from_file(cls, encrypted_text, file: Path):
        with file.open('rb') as f:
            cipher_suite = pickle.load(f)
        return cipher_suite.decrypt(encrypted_text)


@attrs
class User:
    username = attrib(type=str)
    password = attrib(type=str)
    create_date = attrib(type=datetime.datetime)
    left_oil = attrib(type=float)
    others = attrib(type=dict)
    limit_count = attrib(type=int, default=10)

    def __setitem__(self, key, value):
        setattr(self, key, value)


def first_init():
    """
    This function will clear all data from an exist database file!
    It should be only run at first init!
    """
    open(secret_key_file, 'w').close()
    aes = AESEncryption()
    aes.generate_key_file(secret_key_file)
    with db_file.open('wb') as f:
        dumped_bytes = pickle.dumps({})
        f.write(aes.encrypt(dumped_bytes))


class UserDatabaseManager:
    limit_count_per_day = 10

    def __init__(self):
        self.db_data: Optional[dict[str, User]] = None
        self.user_fileds = list(fields_dict(User).keys())  # noqa
        # print([attr for attr in dir(self) if
        #        isinstance(getattr(self, attr), MethodType) and not attr.startswith('_')])

    def __enter__(self):
        self.__open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__save()

    def __open(self):
        with db_file.open('rb') as f:
            loaded_bytes = f.read()
            self.db_data = pickle.loads(AESEncryption.decrypt_from_file(loaded_bytes, secret_key_file))

    def __save(self):
        with db_file.open('wb') as f:
            dumped_bytes = pickle.dumps(self.db_data)
            f.write(AESEncryption.encrypt_from_file(dumped_bytes, secret_key_file))

    def add_user(self, user: User):
        status = True
        if user.username not in self.db_data:
            self.db_data[user.username] = user
        else:
            status = False

        if status is False:
            logger.info(f'add user failed! username:{user.username} already in database!')

        return status

    def del_user(self, username: str):
        status = True
        if username in self.db_data:
            self.db_data.pop(username)
        else:
            status = False

        if status is False:
            logger.info(f'del user failed! {username}')

        return status

    def modify_user(self, username, field, new):
        status = True
        if username in self.db_data:
            if field in self.user_fileds:
                try:
                    self.db_data[username][field] = new
                except Exception:  # noqa
                    status = False
            else:
                status = False
        else:
            status = False

        if status is False:
            logger.info(f'modify user failed! {username, field, new}')

        return status

    def show(self):
        for k, v in self.db_data.items():
            print(k, v)

    def get_by_username(self, username) -> Optional[User]:
        if username in self.db_data:
            return self.db_data[username]
        else:
            return None

    def reset_limit_count(self):
        if self.db_data:
            for k in self.db_data.keys():
                self.db_data[k]['limit_count'] = self.limit_count_per_day


def execute(method: Literal['add_user', 'del_user', 'get_by_username', 'modify_user', 'reset_limit_count', 'show'],
            *args, **kwargs):
    with db_execute_lock:
        with UserDatabaseManager() as manager:
            return getattr(manager, method)(*args, **kwargs)


def event_reset_user_limit_count():
    logger.info('Starting reset user limit count...')
    execute('reset_limit_count')
    logger.info('Reset complete!')


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa
    logger.info('server start...')
    logger.info('Setup scheduler!')
    refresher_scheduler.add_job(func=event_reset_user_limit_count,
                                trigger='cron', hour=0, minute=0)
    refresher_scheduler.start()
    logger.info('Scheduler start working!')
    yield
    logger.info('server over...')


app_udb = FastAPI(lifespan=lifespan)


class RegistRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@app_udb.post('/regist')
def add_user(req: RegistRequest):
    s = time.time()
    resp = {'code': 0, 'msg': 'success'}
    new_user = User(
        username=req.username,
        password=req.password,
        create_date=datetime.datetime.now(),
        left_oil=100.0,
        limit_count=UserDatabaseManager.limit_count_per_day,
        others={}
    )
    status = execute('add_user', new_user)
    if not status:
        resp['code'] = 1
        resp['msg'] = 'username is already in database!'
    logger.info(f'regist used time: {round(time.time() - s, 6)} info: {req.username} {resp["msg"]}')
    return resp


@app_udb.post('/login')
def login(req: LoginRequest):
    s = time.time()
    resp = {'code': 0, 'msg': 'permit'}
    user = execute('get_by_username', req.username)
    if user:
        if not req.password == user.password:
            resp['code'] = 2
            resp['msg'] = 'password not match'
    else:
        resp['code'] = 1
        resp['msg'] = 'username not exist'
    logger.info(f'login used time: {round(time.time() - s, 6)} info: {req.username} {resp["msg"]}')
    return resp


if __name__ == '__main__':
    if db_file.exists() is False:
        first_init()
    execute('show')

    config = Config(app=app_udb, host='localhost', port=8090, workers=8)
    server = Server(config)
    server.run()
