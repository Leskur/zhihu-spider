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
import hmac
import json
import time


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

    def check_login(self):
        """
        检查登录状态，访问登录页面出现跳转则是已登陆
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

    def login(self):
        if self.load_cookies():
            print('读取 cookies 文件')
            if self.check_login():
                print('登录成功')
                return True
            print('Cookies 已过期')

        # 输入知乎账号
        self.check_user_pass()
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

        print(headers)

        login_api = 'https://www.zhihu.com/api/v3/oauth/sign_in'

        encrypt_data = self.encrypt(self.login_data)

        resp = self.session.post(login_api, data=encrypt_data, headers=headers)
        print(resp.text)

        # 登录失败
        if 'error' in resp.text:
            print(resp.json()['error'])
        if self.check_login():
            print('登录成功')
            return True
        print('登录失败')
        return False

    def check_user_pass(self):
        if not self.username:
            self.username = input('请输入知乎账号：')
            if self.username.isdigit() and '+86' not in self.username:
                self.username = '+86' + self.username

        if not self.password:
            self.password = getpass.getpass('请输入密码（输入不可见）：')

    def get_captcha(self):
        """
        请求获取验证码接口，无论是否需要验证码都需要请求一次
        如果需要验证码会返回图片的 base64 编码
        :return:
        """
        api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=en'
        resp = self.session.get(api)
        print(resp.text)
        # 需要验证码
        if resp.json()['show_captcha']:
            resp = self.session.get(api)
            put_resp = self.session.put(api)
            json_data = put_resp.json()
            img_base64 = json_data['img_base64']
            with open('./captcha.jpg', 'wb') as f:
                f.write(base64.b64decode(img_base64))
            img = Image.open('./captcha.jpg')

            # pyplot.imshow(img)
            # print('点击所有倒立的汉字，在命令行中按回车提交')
            #
            # points = pyplot.ginput(7)
            # capt = json.dumps({'img_size': [200, 44],
            #                    'input_points': [[i[0] / 2, i[1] / 2] for i in points]})
            # print(capt)

            img_thread = threading.Thread(target=img.show, daemon=True)
            img_thread.start()
            capt = input('请输入图片里的验证码：')
            # 提交验证码
            r = self.session.post(api, data={'input_text': str(capt)})
            print(r.text)
            return capt
        return ''

    def get_signature(self, timestamp):
        h = hmac.new(b'd1b964811afb40118a12068ff74a12f4', digestmod=hashlib.sha1)
        grant_type = self.login_data['grant_type']
        client_id = self.login_data['client_id']
        source = self.login_data['source']
        h.update(bytes((grant_type + client_id + source + str(timestamp)), 'utf-8'))
        return h.hexdigest()

    @staticmethod
    def encrypt(form_data: dict):
        with open('./encrypt.js') as f:
            js_code = f.read()
            ctx = execjs.compile(js_code)
            encrypt_data = ctx.call('Q', urlencode(form_data))
            return encrypt_data


def authorize(username=None, password=None):
    return Authorize(username, password)
