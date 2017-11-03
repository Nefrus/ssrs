#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
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
import json
import sys
import getopt
import logging
from shadowsocks.common import to_bytes, to_str, IPNetwork, PortRange
from shadowsocks import encrypt


VERBOSE_LEVEL = 5

verbose = 0


def check_python():
    info = sys.version_info
    if info[0] == 2 and not info[1] >= 6:
        print('Python 2.6+ required')
        sys.exit(1)
    elif info[0] == 3 and not info[1] >= 3:
        print('Python 3.3+ required')
        sys.exit(1)
    elif info[0] not in [2, 3]:
        print('Python version not supported')
        sys.exit(1)


def print_exception(e):
    global verbose
    logging.error(e)
    if verbose > 0:
        import traceback
        traceback.print_exc()

def __version():
    version_str = ''
    try:
        import pkg_resources
        version_str = pkg_resources.get_distribution('shadowsocks').version
    except Exception:
        try:
            from shadowsocks import version
            version_str = version.version()
        except Exception:
            pass
    return version_str

def print_shadowsocks():
    print('ShadowsocksR %s' % __version())

def log_shadowsocks_version():
    logging.info('ShadowsocksR %s' % __version())

# 返回配置文件地址  user_config_path 优先级高
def find_config():
    user_config_path = 'user-config.json'
    config_path = 'config.json'

    def sub_find(file_name):
        if os.path.exists(file_name):
            return file_name
        file_name = os.path.join(os.path.abspath('..'), file_name)
        return file_name if os.path.exists(file_name) else None

    return sub_find(user_config_path) or sub_find(config_path)

def check_config(config, is_local):
    # 判断配置文件中是否有 deamon 如果为stop 则返回
    if config.get('daemon', None) == 'stop':
        # no need to specify configuration for daemon stop
        return
    # 在是本地且密码为空的情况下
    # 输出密码未指定 并退出
    if is_local and not config.get('password', None):
        logging.error('password not specified')
        print_help(is_local)
        sys.exit(2)
    # 在非本地且密码或这port_password为空的情况下
    # 输出密码未指定 并退出
    if not is_local and not config.get('password', None) \
            and not config.get('port_password', None):
        logging.error('password or port_password not specified')
        print_help(is_local)
        sys.exit(2)
    # 若配置文件中有 local_port 则进行类型转换
    if 'local_port' in config:
        config['local_port'] = int(config['local_port'])
    # 若配置文件中有 server_port 且 server_port 的类型不是list 则进行类型转换
    if 'server_port' in config and type(config['server_port']) != list:
        config['server_port'] = int(config['server_port'])
    # 若配置文件中 local_address 为 0.0.0.0
    # 则输出警告:本地设置为监听0.0.0.0,它不是安全的
    if config.get('local_address', '') in [b'0.0.0.0']:
        logging.warning('warning: local set to listen on 0.0.0.0, it\'s not safe')
    # 若配置文件中 server 为  127.0.0.1 或者 localhost
    # 则输出警告 服务监听为 127.0.0.1 / localhost 你确定吗？
    if config.get('server', '') in ['127.0.0.1', 'localhost']:
        logging.warning('warning: server set to listen on %s:%s, are you sure?' %
                     (to_str(config['server']), config['server_port']))

    # 若配置文件中 timeout 小于 100 则输出警告 你超时设置的时间太短了
    if config.get('timeout', 300) < 100:
        logging.warning('warning: your timeout %d seems too short' %
                     int(config.get('timeout')))
    # 若配置文件中 timeout 大于 600 则输出警告 你超时设置的时间太长了
    if config.get('timeout', 300) > 600:
        logging.warning('warning: your timeout %d seems too long' %
                     int(config.get('timeout')))
    # 若配置文件中 password 设置为 mypassword 则提示 不要使用默认密码 请在配置文件中更换密码
    if config.get('password') in [b'mypassword']:
        logging.error('DON\'T USE DEFAULT PASSWORD! Please change it in your '
                      'config.json!')
        sys.exit(1)
    # 若配置文件中 user 不问空
    # 判断系统名是否为 Unix
    if config.get('user', None) is not None:
        if os.name != 'posix':
            logging.error('user can be used only on Unix')
            sys.exit(1)
    # 加密机测试
    # 初始化密码
    encrypt.try_cipher(config['password'], config['method'])


def get_config(is_local):
    global verbose
    config = {}
    config_path = None
    # 日志格式设置
    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)-s: %(message)s')
    # 判断是否是本地
    if is_local:
        shortopts = 'hd:s:b:p:k:l:m:O:o:G:g:c:t:vq'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file=', 'user=',
                    'version']
    else:
        shortopts = 'hd:s:p:k:m:O:o:G:g:c:t:vq'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file=', 'workers=',
                    'forbidden-ip=', 'user=', 'manager-address=', 'version']
    try:
        # 命令参数获取
        optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
        for key, value in optlist:
            if key == '-c':
                config_path = value
            elif key in ('-h', '--help'):
                print_help(is_local)
                sys.exit(0)
            elif key == '--version':
                print_shadowsocks()
                sys.exit(0)
            else:
                continue
        # 判断配置文件路径是否存在 若不存在则查找路径
        if config_path is None:
            config_path = find_config()

        # 再次判断配置文件是否存在，若存在 输出配置文件路径
        if config_path:
            logging.debug('loading config from %s' % config_path)
            # 打开配置文件
            with open(config_path, 'rb') as f:
                try:
                    # 解析json并将从unicode转换为str
                    config = parse_json_in_str(remove_comment(f.read().decode('utf8')))
                except ValueError as e:
                    logging.error('found an error in config.json: %s', str(e))
                    sys.exit(1)

        v_count = 0
        # 遍历命令参数
        # -p 设置 port
        # -k 设置 密码
        # -l 设置 local_port
        # -s 设置 server
        # -m 设置 method    加密
        # -O 设置 protocol    协议
        # -o 设置 obfs    混淆
        # -G 设置 protocol_param    协议参数
        # -g 设置 obfs_param    混淆参数
        # -b 设置 local_address
        # -v 设置 v_count 加一 设置 verbose = v_count
        # -t 设置 timeout
        # --fast-open 设置 fast_open
        # --workers 设置 workers 数量
        # --manager-address 设置 manager_address
        # --user 设置 user
        # --forbidden-ip 设置 forbidden_ip
        # -d 设置 daemon
        # --pid-file 设置 pid-file
        # --log-file 设置 log-file
        # -q 设置 v_count 减一 设置 verbose = v_count

        for key, value in optlist:
            if key == '-p':
                config['server_port'] = int(value)
            elif key == '-k':
                config['password'] = to_bytes(value)
            elif key == '-l':
                config['local_port'] = int(value)
            elif key == '-s':
                config['server'] = to_str(value)
            elif key == '-m':
                config['method'] = to_str(value)
            elif key == '-O':
                config['protocol'] = to_str(value)
            elif key == '-o':
                config['obfs'] = to_str(value)
            elif key == '-G':
                config['protocol_param'] = to_str(value)
            elif key == '-g':
                config['obfs_param'] = to_str(value)
            elif key == '-b':
                config['local_address'] = to_str(value)
            elif key == '-v':
                v_count += 1
                # '-vv' turns on more verbose mode
                config['verbose'] = v_count
            elif key == '-t':
                config['timeout'] = int(value)
            elif key == '--fast-open':
                config['fast_open'] = True
            elif key == '--workers':
                config['workers'] = int(value)
            elif key == '--manager-address':
                config['manager_address'] = value
            elif key == '--user':
                config['user'] = to_str(value)
            elif key == '--forbidden-ip':
                config['forbidden_ip'] = to_str(value)

            elif key == '-d':
                config['daemon'] = to_str(value)
            elif key == '--pid-file':
                config['pid-file'] = to_str(value)
            elif key == '--log-file':
                config['log-file'] = to_str(value)
            elif key == '-q':
                v_count -= 1
                config['verbose'] = v_count
            else:
                continue
    except getopt.GetoptError as e:
        print(e, file=sys.stderr)
        print_help(is_local)
        sys.exit(2)

    if not config:
        logging.error('config not specified')
        print_help(is_local)
        sys.exit(2)

    # 类型转换
    config['password'] = to_bytes(config.get('password', b''))
    config['method'] = to_str(config.get('method', 'aes-256-cfb'))
    config['protocol'] = to_str(config.get('protocol', 'origin'))
    config['protocol_param'] = to_str(config.get('protocol_param', ''))
    config['obfs'] = to_str(config.get('obfs', 'plain'))
    config['obfs_param'] = to_str(config.get('obfs_param', ''))
    config['port_password'] = config.get('port_password', None)
    config['additional_ports'] = config.get('additional_ports', {})
    config['additional_ports_only'] = config.get('additional_ports_only', False)
    config['timeout'] = int(config.get('timeout', 300))
    config['udp_timeout'] = int(config.get('udp_timeout', 120))
    config['udp_cache'] = int(config.get('udp_cache', 64))
    config['fast_open'] = config.get('fast_open', False)
    config['workers'] = config.get('workers', 1)
    config['pid-file'] = config.get('pid-file', '/var/run/shadowsocksr.pid')
    config['log-file'] = config.get('log-file', '/var/log/shadowsocksr.log')
    config['verbose'] = config.get('verbose', False)
    config['connect_verbose_info'] = config.get('connect_verbose_info', 0)
    config['local_address'] = to_str(config.get('local_address', '127.0.0.1'))
    config['local_port'] = config.get('local_port', 1080)

    # 判断是否是本地
    if is_local:
        if config.get('server', None) is None:
            logging.error('server addr not specified')
            print_local_help()
            sys.exit(2)
        else:
            config['server'] = to_str(config['server'])
    else:
        # 设置server地址 默认 0.0.0.0
        config['server'] = to_str(config.get('server', '0.0.0.0'))
        try:
            # 设置忽略地址
            config['forbidden_ip'] = \
                IPNetwork(config.get('forbidden_ip', '127.0.0.0/8,::1/128'))
        except Exception as e:
            logging.error(e)
            sys.exit(2)
        try:
            # 设置忽略端口
            config['forbidden_port'] = PortRange(config.get('forbidden_port', ''))
        except Exception as e:
            logging.error(e)
            sys.exit(2)
        try:
            config['ignore_bind'] = \
                IPNetwork(config.get('ignore_bind', '127.0.0.0/8,::1/128,10.0.0.0/8,192.168.0.0/16'))
        except Exception as e:
            logging.error(e)
            sys.exit(2)
    # 获取服务端口 默认8388
    config['server_port'] = config.get('server_port', 8388)

    # 设置日志级别
    logging.getLogger('').handlers = []
    logging.addLevelName(VERBOSE_LEVEL, 'VERBOSE')
    if config['verbose'] >= 2:
        level = VERBOSE_LEVEL
    elif config['verbose'] == 1:
        level = logging.DEBUG
    elif config['verbose'] == -1:
        level = logging.WARN
    elif config['verbose'] <= -2:
        level = logging.ERROR
    else:
        level = logging.INFO
    verbose = config['verbose']
    logging.basicConfig(level=level,
                        format='%(asctime)s %(levelname)-8s %(filename)s:%(lineno)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    # 检查配置
    check_config(config, is_local)

    return config


def print_help(is_local):
    if is_local:
        print_local_help()
    else:
        print_server_help()


def print_local_help():
    print('''usage: sslocal [OPTION]...
A fast tunnel proxy that helps you bypass firewalls.

You can supply configurations via either config file or command line arguments.

Proxy options:
  -c CONFIG              path to config file
  -s SERVER_ADDR         server address
  -p SERVER_PORT         server port, default: 8388
  -b LOCAL_ADDR          local binding address, default: 127.0.0.1
  -l LOCAL_PORT          local port, default: 1080
  -k PASSWORD            password
  -m METHOD              encryption method, default: aes-256-cfb
  -o OBFS                obfsplugin, default: http_simple
  -t TIMEOUT             timeout in seconds, default: 300
  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+

General options:
  -h, --help             show this help message and exit
  -d start/stop/restart  daemon mode
  --pid-file PID_FILE    pid file for daemon mode
  --log-file LOG_FILE    log file for daemon mode
  --user USER            username to run as
  -v, -vv                verbose mode
  -q, -qq                quiet mode, only show warnings/errors
  --version              show version information

Online help: <https://github.com/shadowsocks/shadowsocks>
''')


def print_server_help():
    print('''usage: ssserver [OPTION]...
A fast tunnel proxy that helps you bypass firewalls.

You can supply configurations via either config file or command line arguments.

Proxy options:
  -c CONFIG              path to config file
  -s SERVER_ADDR         server address, default: 0.0.0.0
  -p SERVER_PORT         server port, default: 8388
  -k PASSWORD            password
  -m METHOD              encryption method, default: aes-256-cfb
  -o OBFS                obfsplugin, default: http_simple
  -t TIMEOUT             timeout in seconds, default: 300
  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+
  --workers WORKERS      number of workers, available on Unix/Linux
  --forbidden-ip IPLIST  comma seperated IP list forbidden to connect
  --manager-address ADDR optional server manager UDP address, see wiki

General options:
  -h, --help             show this help message and exit
  -d start/stop/restart  daemon mode
  --pid-file PID_FILE    pid file for daemon mode
  --log-file LOG_FILE    log file for daemon mode
  --user USER            username to run as
  -v, -vv                verbose mode
  -q, -qq                quiet mode, only show warnings/errors
  --version              show version information

Online help: <https://github.com/shadowsocks/shadowsocks>
''')


def _decode_list(data):
    rv = []
    for item in data:
        if hasattr(item, 'encode'):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.items():
        if hasattr(value, 'encode'):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv

class JSFormat:
    def __init__(self):
        self.state = 0

    def push(self, ch):
        ch = ord(ch)
        if self.state == 0:
            if ch == ord('"'):
                self.state = 1
                return to_str(chr(ch))
            elif ch == ord('/'):
                self.state = 3
            else:
                return to_str(chr(ch))
        elif self.state == 1:
            if ch == ord('"'):
                self.state = 0
                return to_str(chr(ch))
            elif ch == ord('\\'):
                self.state = 2
            return to_str(chr(ch))
        elif self.state == 2:
            self.state = 1
            if ch == ord('"'):
                return to_str(chr(ch))
            return "\\" + to_str(chr(ch))
        elif self.state == 3:
            if ch == ord('/'):
                self.state = 4
            else:
                return "/" + to_str(chr(ch))
        elif self.state == 4:
            if ch == ord('\n'):
                self.state = 0
                return "\n"
        return ""

def remove_comment(json):
    fmt = JSFormat()
    return "".join([fmt.push(c) for c in json])


def parse_json_in_str(data):
    # parse json and convert everything from unicode to str
    return json.loads(data, object_hook=_decode_dict)
