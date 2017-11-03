#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2012-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging

from shadowsocks import common
from shadowsocks.crypto import rc4_md5, openssl, sodium, table


method_supported = {}
method_supported.update(rc4_md5.ciphers)
method_supported.update(openssl.ciphers)
method_supported.update(sodium.ciphers)
method_supported.update(table.ciphers)

# 返回n个随机byte值的string，作为加密使用
def random_string(length):
    try:
        return os.urandom(length)
    except NotImplementedError as e:
        return openssl.rand_bytes(length)

cached_keys = {}


def try_cipher(key, method=None):
    Encryptor(key, method)


def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    # 判断密码是否有 encode 属性
    # 若存在 encode 属性 将密码通过 utf-8 编码
    if hasattr(password, 'encode'):
        password = password.encode('utf-8')
    # cached_key 属性赋值
    cached_key = '%s-%d-%d' % (password, key_len, iv_len)
    # 从 cached_keys 中获取 cached_key 若不存在则返回 None
    r = cached_keys.get(cached_key, None)
    # 若存在 cached_key ， 将key返回
    if r:
        return r

    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        # 获取md5对象
        md5 = hashlib.md5()
        # 将 password 赋值给data
        data = password
        # 当次数大于1时 data 等于上次加密信息 加上密码
        if i > 0:
            data = m[i - 1] + password
        # md5加密
        md5.update(data)
        # 获取加密信息并加入m
        m.append(md5.digest())
        i += 1
    # 获取加密后的值
    ms = b''.join(m)
    # key 为前 key_len 长度的二进制值
    key = ms[:key_len]
    # iv 为 key_len 至 key_len + iv_len 长度的二进制值
    iv = ms[key_len:key_len + iv_len]

    cached_keys[cached_key] = (key, iv)
    return key, iv


class Encryptor(object):
    def __init__(self, key, method, iv = None):
        self.key = key
        self.method = method
        self.iv = None
        self.iv_sent = False
        self.cipher_iv = b''
        self.iv_buf = b''
        self.cipher_key = b''
        self.decipher = None
        method = method.lower()
        # 获取加密信息
        self._method_info = self.get_method_info(method)
        if self._method_info:
            # 若vi为空或者长度不等于加密信息长度
            # 则重新获取
            if iv is None or len(iv) != self._method_info[1]:
                self.cipher = self.get_cipher(key, method, 1,
                                          random_string(self._method_info[1]))
            else:
                self.cipher = self.get_cipher(key, method, 1, iv)
        else:
            logging.error('method %s not supported' % method)
            sys.exit(1)

    def get_method_info(self, method):
        method = method.lower()
        m = method_supported.get(method)
        return m

    def iv_len(self):
        return len(self.cipher_iv)

    def get_cipher(self, password, method, op, iv):
        # 以utf-8编码对unicode对像进行编码
        password = common.to_bytes(password)
        # 获取加密信息
        m = self._method_info
        # 当 key 长度大于 0 时，获取加密后的 key，iv
        if m[0] > 0:
            key, iv_ = EVP_BytesToKey(password, m[0], m[1])
        else:
            # key_length == 0 indicates we should use the key directly
            key, iv = password, b''
        iv = iv[:m[1]]

        # 设置 cipher_key、cipher_iv
        if op == 1:
            # this iv is for cipher not decipher
            # 这个 'iv' 是密码破译
            self.cipher_iv = iv[:m[1]]
        self.cipher_key = key
        return m[2](method, key, iv, op)

    def encrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.iv_sent:
            return self.cipher.update(buf)
        else:
            self.iv_sent = True
            return self.cipher_iv + self.cipher.update(buf)

    def decrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.decipher is not None: #optimize
            return self.decipher.update(buf)

        decipher_iv_len = self._method_info[1]
        if len(self.iv_buf) <= decipher_iv_len:
            self.iv_buf += buf
        if len(self.iv_buf) > decipher_iv_len:
            decipher_iv = self.iv_buf[:decipher_iv_len]
            self.decipher = self.get_cipher(self.key, self.method, 0,
                                            iv=decipher_iv)
            buf = self.iv_buf[decipher_iv_len:]
            del self.iv_buf
            return self.decipher.update(buf)
        else:
            return b''

def encrypt_all(password, method, op, data):
    result = []
    method = method.lower()
    (key_len, iv_len, m) = method_supported[method]
    if key_len > 0:
        key, _ = EVP_BytesToKey(password, key_len, iv_len)
    else:
        key = password
    if op:
        iv = random_string(iv_len)
        result.append(iv)
    else:
        iv = data[:iv_len]
        data = data[iv_len:]
    cipher = m(method, key, iv, op)
    result.append(cipher.update(data))
    return b''.join(result)

def encrypt_key(password, method):
    method = method.lower()
    (key_len, iv_len, m) = method_supported[method]
    if key_len > 0:
        key, _ = EVP_BytesToKey(password, key_len, iv_len)
    else:
        key = password
    return key

def encrypt_iv_len(method):
    method = method.lower()
    (key_len, iv_len, m) = method_supported[method]
    return iv_len

def encrypt_new_iv(method):
    method = method.lower()
    (key_len, iv_len, m) = method_supported[method]
    return random_string(iv_len)

def encrypt_all_iv(key, method, op, data, ref_iv):
    result = []
    method = method.lower()
    (key_len, iv_len, m) = method_supported[method]
    if op:
        iv = ref_iv[0]
        result.append(iv)
    else:
        iv = data[:iv_len]
        data = data[iv_len:]
        ref_iv[0] = iv
    cipher = m(method, key, iv, op)
    result.append(cipher.update(data))
    return b''.join(result)


CIPHERS_TO_TEST = [
    'aes-128-cfb',
    'aes-256-cfb',
    'rc4-md5',
    'salsa20',
    'chacha20',
    'table',
]


def test_encryptor():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        encryptor = Encryptor(b'key', method)
        decryptor = Encryptor(b'key', method)
        cipher = encryptor.encrypt(plain)
        plain2 = decryptor.decrypt(cipher)
        assert plain == plain2


def test_encrypt_all():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        cipher = encrypt_all(b'key', method, 1, plain)
        plain2 = encrypt_all(b'key', method, 0, cipher)
        assert plain == plain2


if __name__ == '__main__':
    test_encrypt_all()
    test_encryptor()
