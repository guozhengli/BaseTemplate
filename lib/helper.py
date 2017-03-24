# coding: utf-8
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.conf import settings
from django import forms
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

import re
import smtplib
from email.mime.text import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.MIMEImage import MIMEImage

def paginator(data, paginate_num=10, page_num=1):
    '''
    分页机制
    :param data: 数据
    :param paginate_num: 一页显示行数
    :param page_num: 显示的页数
    :return:
    '''
    paginator = Paginator(data, paginate_num)
    try:
        contacts = paginator.page(page_num)
    except PageNotAnInteger:
        contacts = paginator.page(1)
    except EmptyPage:
        contacts = paginator.page(paginator.num_pages)
    return contacts

class prpcrypt():
    '''
    AES双向加密解密类
    pc = prpcrypt('keyskeyskeyskeys')  # 初始化密钥
    e = pc.encrypt("00000")
    d = pc.decrypt(e)
    print e, d
    e = pc.encrypt("00000000000000000000000000")
    d = pc.decrypt(e)
    print e, d
    #random.sample("abcdefghijklmnopqrstovwxyzABCDEFGHIJKLMNOPQRSTOVWXYZ1234567890!@#$%^&*", 32)
    '''
    def __init__(self, key=''):
        if key:
            self.key = key
        else:
            self.key = "NROfC$nvmV^EQpAI"
        self.mode = AES.MODE_CBC

    # 加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数
    def encrypt(self, text):
        if not text:
            text = ""
        cryptor = AES.new(self.key, self.mode, self.key)
        # 这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.目前AES-128足够用
        length = 16
        count = len(text)
        add = length - (count % length)
        text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        if not text:
            return ""
        cryptor = AES.new(self.key, self.mode, self.key)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')



def get_source_ip(request):
    if request.META.has_key('HTTP_X_FORWARDED_FOR'):
        source_ip = request.META['HTTP_X_FORWARDED_FOR']
    else:
        source_ip = request.META['REMOTE_ADDR']
    return source_ip

class Mail(object):
    """
    mail = Mail()
        mail.send('liutf@zgxcw.com', '测试而已', '是的只是测试')
    """

    def __init__(self):

        self.mail_server = settings.ADMINSET_MAIL_SERVER
        self.mail_port = settings.ADMINSET_MAIL_PORT
        self.mail_user = settings.ADMINSET_MAIL_USER
        self.mail_password = settings.ADMINSET_MAIL_PASSWORD
        self.msg = MIMEMultipart('alternative')
        self.smtp = None
        self.debug = False
        self.header = ""


    def send(self, to, subject, content):
        ok = self.connect()
        if not ok:
            return False
        self.head(to, self.mail_user, subject)
        self.message(content)
        ok = self._send()
        if not ok:
            return False
        self.quit()
        return True

    def connect(self):
        try:
            self.smtp = smtplib.SMTP_SSL(self.mail_server, self.mail_port, timeout=10)
            self.smtp.ehlo()
            self.smtp.set_debuglevel(self.debug)
            self.smtp.login(self.mail_user, self.mail_password)
            return True
        except Exception,e:

            return False

    def _send(self):
        try:
            self.smtp.sendmail(self.msg['From'], self.msg['To'], self.msg.as_string())
            return True
        except Exception,e:
            return False

    def head(self, toaddr, fromaddr, title):
        self.msg['From'] = fromaddr
        self.msg['To'] = toaddr
        self.msg['Subject'] = title

    def message(self, msg):
        con = MIMEText(msg, 'html', 'utf-8')
        self.msg.attach(con)

    def quit(self):
        if (self.smtp):
            self.smtp.quit()


def check_password(password):
    # 密码不能小于8位
    if len(password) < 8:
         raise forms.ValidationError(u"验证失败！密码过短，至少8位！")
    # 密码过于简单，不包括特殊字符（~!@#$%^&*?><）
    # if not re.match(r'.*[~!@#$%^&*?><]+', password):
    #     raise forms.ValidationError(u"密码过于简单，至少包括一个特殊字符(~!@#$%^&*?><)")
    # 至少一个数字
    if not re.match(r'.*[0-9]+', password):
        raise forms.ValidationError(u'密码过于简单，至少包括一个数字')
    # 至少一个小写字母
    if not re.match(r'.*[a-z]+', password):
        raise forms.ValidationError(u'密码过于简单，至少包括一个小写字母')
    # 至少一个大写字母
    if not re.match(r'.*[A-Z]+', password):
        raise forms.ValidationError(u'密码过于简单，至少包括一个大写字母')


def split_line_from_textarea(data):
    '''
    将Textarea输入的数据按行分割
    :return:
    '''
    if "|" in data:
        lines = data.strip().split("|")
    else:
        lines = data.strip().split("\n")
    res = [line.strip() for line in lines if line.strip()]
    return res

