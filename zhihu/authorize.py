from requests.cookies import cookielib
from urllib.parse import urlencode
from matplotlib import pyplot
from PIL import Image
import threading
import requests
import execjs
import getpass
import hashlib
import base64
import json
import hmac
import time
import os


class Authorize(object):
    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password

        self.login_data = {
            'client_id': 'c3cef7c66a1843f8b3a9e6a1e3160e20',
            'grant_type': 'password',
            'source': 'com.zhihu.web',
            'username': '',
            'password': '',
            'lang': 'en',
            'ref_source': 'homepage',
            'utm_source': '',
        }

        self.session = requests.session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) '
                          'AppleWebKit/605.1.15 (KHTML, like Gecko) '
                          'Version/12.0.3 Safari/605.1.15'
        }
        self.session.cookies = cookielib.LWPCookieJar(filename='./cookies.txt')

    def load_cookies(self):
        """
        读取 Cookies 文件 加载到 Session
        :return: bool
        """
        try:
            self.session.cookies.load(ignore_discard=True)
            return True
        except FileNotFoundError:
            return False

    def get_xsrf(self):
        """
        从登录页面获取 xsrf
        :return: String
        """
        _xsrf = str()
        self.session.get('https://www.zhihu.com/', allow_redirects=False)
        for c in self.session.cookies:
            if c.name == '_xsrf':
                _xsrf = c.value

        return _xsrf

    def verify_user_pass(self):
        """
        验证用户名和密码是否已存在，若无则手动输入
        :return: None
        """
        if not self.username:
            self.username = input('请输入知乎账号：')
            if self.username.isdigit() and '+86' not in self.username:
                self.username = '+86' + self.username

        if not self.password:
            self.password = getpass.getpass('请输入密码（输入不可见）：')

    def login(self):
        if self.load_cookies():
            print('读取 cookies 文件')
            if self.verify_login():
                print('登录成功')
                return True
            print('Cookies 已过期')

        # 验证账号密码
        self.verify_user_pass()
        self.login_data.update({
            'username': self.username,
            'password': self.password
        })

        timestamp = int(time.time() * 1000)
        self.login_data.update({
            'captcha': self.get_captcha(),
            'timestamp': timestamp,
            'signature': self.get_signature(timestamp)
        })

        headers = self.session.headers.copy()
        headers.update({
            'x-xsrftoken': self.get_xsrf(),
            'X-Zse-83': '3_1.1',  # 不带该参数会提示：请求参数异常，请升级客户端后重试
            'Content-Type': 'application/x-www-form-urlencoded'  # 不带该参数会提示："Missing argument grant_type
        })

        login_api = 'https://www.zhihu.com/api/v3/oauth/sign_in'

        encrypt_data = self.encrypt(self.login_data)

        resp = self.session.post(login_api, data=encrypt_data, headers=headers)
        print(resp.text)

        # 登录失败
        if 'error' in resp.text:
            print(resp.json()['error'])
        if self.verify_login():
            print('登录成功')
            return True
        print('登录失败')
        return False

    def verify_login(self):
        """
        验证是否登录成功，访问登录页面出现跳转则是登录成功
        如果登录成功则保存当前 Cookies
        :return: bool
        """
        login_url = 'https://www.zhihu.com/signup'
        resp = self.session.get(login_url, allow_redirects=False)
        print(resp.status_code)
        if resp.status_code == 302:
            self.session.cookies.save()
            return True
        return False

    def get_signature(self, timestamp):
        """
        通过 Hmac 算法计算获取签名
        通过几个固定字符串加时间戳，具体规则从知乎查看
        :param timestamp: 时间戳
        :return: str
        """
        h = hmac.new(b'd1b964811afb40118a12068ff74a12f4', digestmod=hashlib.sha1)
        grant_type = self.login_data['grant_type']
        client_id = self.login_data['client_id']
        source = self.login_data['source']
        h.update(bytes((grant_type + client_id + source + str(timestamp)), 'utf-8'))
        return h.hexdigest()

    def get_captcha(self, lang='en'):
        """
        请求获取验证码接口，无论是否需要验证码都需要请求一次
        如果需要验证码会返回图片的 base64 编码
        根据 lang 参数匹配验证码类型 (en/cn)
        :param lang: 验证码的语言 (en/cn)
        :return: 验证码的 POST 参数
        """
        if lang == 'en':
            api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=en'
        else:
            api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=cn'
        resp = self.session.get(api)

        # 需要验证
        if resp.json()['show_captcha']:
            # 获取验证码 base64
            put_resp = self.session.put(api)
            json_data = put_resp.json()
            img_base64 = json_data['img_base64']

            # 以二进制方式打开验证码图片，存在则覆盖，不存在则创建
            with open('./captcha.jpg', 'wb') as f:
                f.write(base64.b64decode(img_base64))
            img = Image.open('./captcha.jpg')

            # 英文验证
            if lang == 'en':
                img_thread = threading.Thread(target=img.show, daemon=True)
                img_thread.start()
                captcha = input('请输入图片里的验证码：')

            # 中文验证
            else:
                pyplot.imshow(img)
                print('点击所有倒立的汉字，按回车提交')
                points = pyplot.ginput(7)
                captcha = json.dumps({'img_size': [200, 44], 'input_points': [[i[0] / 2, i[1] / 2] for i in points]})

            # 获取验证码数据后，删除验证码图片文件
            os.remove('./captcha.jpg')

            # 调用验证码接口验证
            self.verify_captcha(lang=lang, captcha=captcha)
            return captcha

        # 不需要验证
        return ''

    def verify_captcha(self, lang='en', captcha=None):
        """
        验证码验证，返回是否验证成功
        :param lang: 验证码类型 (en/cn)
        :param captcha: 验证码数据
        :return: bool
        """
        if lang == 'en':
            api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=en'
        else:
            api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=cn'
        resp = self.session.post(api, data={'input_text': captcha})
        return bool(resp.json()['success'])

    @staticmethod
    def encrypt(form_data: dict):
        """
        加密 FormData
        :param form_data:
        :return: 加密后的 FormData
        """
        with open('./encrypt.js') as f:
            js_code = f.read()
            ctx = execjs.compile(js_code)
            encrypt_data = ctx.call('Q', urlencode(form_data))
            return encrypt_data


def authorize(username=None, password=None):
    return Authorize(username, password)
