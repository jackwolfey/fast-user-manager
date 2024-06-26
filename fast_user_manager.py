# -*- coding: utf-8 -*-
# Author: Wei Jia
# Project: play_ground
# File: fast_user_manager.py
import argparse
import datetime
import os
import pickle
import re
import string
import time
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import Optional, Union

import cryptography
from apscheduler.schedulers.background import BackgroundScheduler
from attr import define, field, fields_dict, Factory
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from filelock import FileLock
from funfunc import get_basic_logger
from pydantic import BaseModel
from pywebio import input, output, pin
from pywebio.platform.fastapi import webio_routes
from pywebio_battery import popup_input
from uvicorn import Config, Server

logger = get_basic_logger()

# 可配置的系统环境变量,使用控制面板必须同时定义ADMIN_*这两项
SHOW_PASSWORD = os.getenv('SHOW_PASSWORD', False)
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', None)
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', None)

if SHOW_PASSWORD == '1':
    SHOW_PASSWORD = True
else:
    SHOW_PASSWORD = False

db_execute_lock = FileLock('./db_secret.key.lock', timeout=5)
secret_key_file = Path('./db_secret.key')
db_file = Path('./user_data.pdb').absolute()

refresher_scheduler = BackgroundScheduler()

TABLE_CENTER_STYLE = 'display: flex;justify-content: center;align-items: center;text-align: center;'


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


class UsernameInvalid(ValueError):
    ...


class PasswordInvalid(ValueError):
    ...


@define(kw_only=True)
class UserOtherInfo:
    history = field(type=Optional[Union[dict, list]], default=None)
    email = field(type=str, default="")


@define(kw_only=True)
class User:
    username = field(type=str, converter=str)
    password = field(type=str, converter=str, repr=lambda x: '******')
    create_date = field(type=datetime.datetime, default=Factory(datetime.datetime.now))
    left_oil = field(type=int, default=100)
    others = field(type=UserOtherInfo, default=UserOtherInfo())

    def __setitem__(self, key, value):
        setattr(self, key, value)

    @username.validator
    def check_username(self, _, username):
        if len(username) > 20:
            raise UsernameInvalid("username's length must lower than 20")

        for c in username:
            if c not in string.ascii_letters + string.digits + "_":
                if bool(re.match('[\u4e00-\u9fff]', c)) is False:
                    raise UsernameInvalid("invalid char in username, must be ascii letters, digits or '_'")

    @password.validator
    def check_password(self, _, password):
        if len(password) < 8 or len(password) > 20:
            raise PasswordInvalid("password's length must greater than 8 and lower than 20")

        valid_char_set = string.ascii_letters + string.digits + string.punctuation
        _has_upper = False
        _has_lower = False
        _has_digit = False
        for c in password:
            if c not in valid_char_set:
                raise PasswordInvalid("invalid char in password, must be ascii letters, digits or common punctuation")
            if _has_upper is False and c.isupper():
                _has_upper = True
            if _has_lower is False and c.islower():
                _has_lower = True
            if _has_digit is False and c.isdigit():
                _has_digit = True

        if not (_has_upper and _has_digit and _has_lower):
            raise PasswordInvalid("invalid password, must contain upper letter, lower letter and digit")


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
    def __init__(self):
        self.db_data: Optional[dict[str, User]] = None
        self.user_fields = list(fields_dict(User).keys())

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

    def read_only(self):
        self.__open()
        return self.db_data

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

    def modify_user(self, username, fieldnames, new):
        status = True
        if username in self.db_data:
            if fieldnames in self.user_fields:
                try:
                    self.db_data[username][fieldnames] = new
                except Exception:  # noqa
                    status = False
            else:
                status = False
        else:
            status = False

        if status is False:
            logger.info(f'modify user failed! {username, fieldnames, new}')

        return status

    def show(self):
        for k, v in self.db_data.items():
            print(k, v)

    def get_by_username(self, username) -> Optional[User]:
        if username in self.db_data:
            return self.db_data[username]
        else:
            return None


# For typing
class ExecuteOption:
    add_user = 'add_user'
    del_user = 'del_user'
    get_by_username = 'get_by_username'
    modify_user = 'modify_user'
    show = 'show'


def execute(method: str, *args, **kwargs):
    with db_execute_lock:
        with UserDatabaseManager() as manager:
            return getattr(manager, method)(*args, **kwargs)


def internal_control_panel():
    """
    内部控制面板

    内部控制面板
    """

    def _webio_check_password(password):
        if len(password) < 8 or len(password) > 20:
            return False

        valid_char_set = string.ascii_letters + string.digits + string.punctuation
        _has_upper = False
        _has_lower = False
        _has_digit = False
        for c in password:
            if c not in valid_char_set:
                raise False
            if _has_upper is False and c.isupper():
                _has_upper = True
            if _has_lower is False and c.islower():
                _has_lower = True
            if _has_digit is False and c.isdigit():
                _has_digit = True

        if not (_has_upper and _has_digit and _has_lower):
            return False

        return True

    def _webio_check_username(username):
        if len(username) > 20:
            return False

        for c in username:
            if c not in string.ascii_letters + string.digits + "_":
                if bool(re.match('[\u4e00-\u9fff]', c)) is False:
                    return False

        return True

    def _add_oil(username, cur_oil):
        def _pop_up_input():
            user_input = popup_input(title="添加数量", pins=[
                output.put_text(f'正在修改:{username} 请输入添加的数量'),
                pin.put_input(name="_v", type=input.NUMBER)
            ], cancelable=True)
            if user_input:
                _add_value = user_input['_v']
                return _add_value

        add_value = _pop_up_input()
        if add_value:
            execute(ExecuteOption.modify_user, username, "left_oil", cur_oil + add_value)
            output.toast("添加成功")
            _refresh_tabel()

    def _del_user(username):
        execute(ExecuteOption.del_user, username)
        output.toast(f"删除用户:{username} 成功")
        _refresh_tabel()

    def _change_pw(username):
        def _pop_up_input_pw():
            def _validate_pw(data):
                if _webio_check_password(data['_p1']) is False:
                    return "_p1", "不合法的密码!"
                if data['_p1'] != data['_p2']:
                    return "_p1", "两次输入的密码不一致!"

            user_input = popup_input(title="修改密码", pins=[
                output.put_text(f'正在修改:{username} 请输入新密码'),
                pin.put_input(name="_p1", type=input.PASSWORD),
                output.put_text('再次确认密码'),
                pin.put_input(name='_p2', type=input.PASSWORD)
            ], cancelable=True, validate=_validate_pw)
            if user_input:
                _new_pw = user_input['_p1']
                return _new_pw

        new_pw = _pop_up_input_pw()
        if new_pw:
            execute(ExecuteOption.modify_user, username, "password", new_pw)
            output.toast(f"用户:{username} 密码修改成功")
            _refresh_tabel()

    def _add_user():
        def _check_pw12(data):
            if _webio_check_username(data['_un']) is False:
                return "_un", "不合法的用户名!"
            if _webio_check_username(data['_pw']) is False:
                return "_pw", "不合法的密码!"
            if data['_pw'] != data['_pw2']:
                return '_pw', "两次输入的密码不一致!"

        user_input = popup_input(title="添加新用户", pins=[
            pin.put_input(name="_un", type=input.TEXT, label="用户名"),
            pin.put_input(name="_pw", type=input.PASSWORD, label="密码"),
            pin.put_input(name="_pw2", type=input.PASSWORD, label="确认密码")
        ], cancelable=True, validate=_check_pw12)
        if user_input:
            un, pw = user_input['_un'], user_input['_pw']
            flag = execute(ExecuteOption.add_user, User(username=un, password=pw))
            if flag:
                output.toast(f"添加用户:{un} 成功")
                _refresh_tabel()
            else:
                output.toast("添加失败")

    def _refresh_tabel():
        content = UserDatabaseManager().read_only()
        tabel_content = [["序号", "用户名", "密码", "创建时间", "剩余次数", "操作"]]
        idx = 0
        for v in content.values():
            tabel_content.append(
                [idx, v.username, v.password if int(SHOW_PASSWORD) else "*" * len(v.password),
                 v.create_date.strftime('%y.%m.%d %H:%M:%S'),
                 v.left_oil, output.put_buttons([{"label": "添加次数", "value": "_add_oil"},
                                                 {"label": "删除", "value": "_del", "color": "danger"},
                                                 {"label": "修改密码", "value": "_cpw", "color": "warning"}
                                                 ],
                                                onclick=[partial(_add_oil, v.username, v.left_oil),
                                                         partial(_del_user, v.username),
                                                         partial(_change_pw, v.username)])])
            idx += 1
        with output.use_scope("TABEL", clear=True):
            output.put_table(tabel_content).style(TABLE_CENTER_STYLE)
            output.put_buttons([{"label": "刷新", "value": "refresh"},
                                {"label": "添加新用户", "value": "add_new", "color": "success"}],
                               onclick=[lambda: _refresh_tabel(), lambda: _add_user()], group=False)

    def _login():
        if pin.pin["admin_username"] == ADMIN_USERNAME and pin.pin["admin_password"] == ADMIN_PASSWORD:
            output.toast("登录成功!")
            output.clear("login")
            _refresh_tabel()
        else:
            output.toast("登录失败! 账户名或密码错误")

    output.put_markdown("# 内部控制面板")
    if ADMIN_USERNAME is None or ADMIN_PASSWORD is None:
        output.put_markdown("## 管理员账户名或管理员账户密码未定义,控制面板被禁用!")
        return None
    with output.use_scope("login", clear=True):
        pin.put_input(name="admin_username", label="管理员账户名:", type=input.TEXT)
        pin.put_input(name="admin_password", label="管理员账户密码:", type=input.PASSWORD)
        output.put_button(label="登录", onclick=lambda: _login())


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa
    logger.info('server start...')

    # 添加定时任务
    # logger.info('Setup scheduler!')
    # refresher_scheduler.add_job(func=None, trigger='cron', hour=0, minute=0)
    # refresher_scheduler.start()
    # logger.info("Scheduler start working!")

    yield
    logger.info('server over...')


app_udb = FastAPI(lifespan=lifespan)

app_udb.add_middleware(
    CORSMiddleware,  # noqa
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


class IsAllowedRequest(BaseModel):
    username: str


class RegisterRequest(IsAllowedRequest):
    password: str


class LoginRequest(RegisterRequest):
    ...


class RegisterResponse(BaseModel):
    code: int
    msg: str


class LoginResponse(RegisterResponse):
    ...


class IsAllowedResponse(RegisterResponse):
    allowed: bool


app_udb.mount("/webio_static", StaticFiles(directory='./webio_static'), name='static')
app_udb.mount("/control_panel", FastAPI(routes=webio_routes(internal_control_panel, cdn="/webio_static")))


@app_udb.post('/register', response_model=RegisterResponse)
def add_user(req: RegisterRequest):
    s = time.time()
    resp = {'code': 0, 'msg': 'success'}
    try:
        new_user = User(username=req.username, password=req.password)
    except UsernameInvalid as e:
        resp['code'] = 2
        resp['msg'] = str(e)
    except PasswordInvalid as e:
        resp['code'] = 3
        resp['msg'] = str(e)
    else:
        status = execute(ExecuteOption.add_user, new_user)
        if not status:
            resp['code'] = 1
            resp['msg'] = 'username is already in database!'
    logger.info(f'register used time: {round(time.time() - s, 6)} info: {req.username} {resp["msg"]}')
    return resp


@app_udb.post('/login', response_model=LoginResponse)
def login(req: LoginRequest):
    s = time.time()
    resp = {'code': 0, 'msg': 'permit'}
    user = execute(ExecuteOption.get_by_username, req.username)
    if user:
        if not req.password == user.password:
            resp['code'] = 2
            resp['msg'] = 'password not match'
    else:
        resp['code'] = 1
        resp['msg'] = 'username not exist'
    logger.info(f'login used time: {round(time.time() - s, 6)} info: {req.username} {resp["msg"]}')
    return resp


@app_udb.post('/is_allowed', response_model=IsAllowedResponse)
def is_allowed(req: IsAllowedRequest):
    s = time.time()
    resp = {'code': 0, 'allowed': True, 'msg': 'success'}
    user = execute(ExecuteOption.get_by_username, req.username)
    if user:
        if user.left_oil >= 1:
            execute(ExecuteOption.modify_user, user.username, 'left_oil', user.left_oil - 1)
            logger.info(f'username:{user.username}, left oil is: {user.left_oil - 1}')
        else:
            resp['allowed'] = False
            resp['msg'] = 'user\'s left oil is empty'
    else:
        resp['code'] = 1
        resp['allowed'] = False
        resp['msg'] = 'username not exist'
    logger.info(f'is_allowed used time: {round(time.time() - s, 6)} info: {req.username} {resp["msg"]}')
    return resp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, default='localhost', help='Service host')
    parser.add_argument('-p', '--port', type=int, default=8000, help='Service port')
    parser.add_argument('-w', '--workers', type=int, default=1, help='Service workers')
    args = parser.parse_args()

    if db_file.exists() is False:
        first_init()
    execute(ExecuteOption.show)

    config = Config(app=app_udb, host=args.host, port=args.port, workers=args.workers)
    server = Server(config)
    server.run()


if __name__ == '__main__':
    main()
