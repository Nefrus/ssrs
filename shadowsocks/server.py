#!/usr/bin/env python
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

import sys
import os
import logging
import signal

if __name__ == '__main__':
    import inspect
    file_path = os.path.dirname(os.path.realpath(inspect.getfile(inspect.currentframe())))
    sys.path.insert(0, os.path.join(file_path, '../'))

from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, \
    asyncdns, manager, common


def main():
    # python版本检查
    shell.check_python()
    # 配置文件获取 并初始化
    # TODO  # check_config(config, is_local) 被我注释掉了 因为本地没有openssl 会报错
    config = shell.get_config(False)
    # 打印 python 版本
    shell.log_shadowsocks_version()
    # 指令
    daemon.daemon_exec(config)

    try:
        # resource 载入
        import resource
        logging.info('current process RLIMIT_NOFILE resource: soft %d hard %d'  % resource.getrlimit(resource.RLIMIT_NOFILE))
    except ImportError:
        pass
    # 判断 port_password 是否存在
    if config['port_password']:
        pass
    else:
        # 在没有 port_password 时
        # 初始化 port_password
        config['port_password'] = {}
        # server_port 赋值
        server_port = config['server_port']
        # 若 server_port 是一个list
        if type(server_port) == list:
            # 遍历 server_port 将 config['port_password'][对应端口] 赋值为 config['password']
            for a_server_port in server_port:
                config['port_password'][a_server_port] = config['password']
        else:
            # 将 config['port_password'][对应端口] 赋值为 config['password']
            config['port_password'][str(server_port)] = config['password']
    # 若配置文件中 dns_ipv6 设置为false
    if not config.get('dns_ipv6', False):
        # asyncdns.IPV6_CONNECTION_SUPPORT 设置为 False
        asyncdns.IPV6_CONNECTION_SUPPORT = False
    # 获取管理地址
    if config.get('manager_address', 0):
        logging.info('entering manager mode')
        # TODO 暂时略过
        manager.run(config)
        return

    tcp_servers = []
    udp_servers = []
    # 获取 dns_resolver 对象
    dns_resolver = asyncdns.DNSResolver()

    # 判断 workers 初始化 stat_counter_dict
    if int(config['workers']) > 1:
        stat_counter_dict = None
    else:
        stat_counter_dict = {}
    # 获取port_password
    port_password = config['port_password']
    # 获取 config_password
    config_password = config.get('password', 'm')
    # 删除 config['port_password']
    del config['port_password']
    # 遍历 port_password
    for port, password_obfs in port_password.items():
        # 获取加密方式
        method = config["method"]
        # 获取协议 默认'origin'
        protocol = config.get("protocol", 'origin')
        # 获取协议参数
        protocol_param = config.get("protocol_param", '')
        # 获取混淆
        obfs = config.get("obfs", 'plain')
        # 获取混淆参数
        obfs_param = config.get("obfs_param", '')
        # bind
        bind = config.get("out_bind", '')
        # bindv6
        bindv6 = config.get("out_bindv6", '')

        # 判断 password_obfs 是否是list
        # 若是list
        # 第一个参数为密码
        # 第二个参数为混淆
        #第三个参数为协议
        if type(password_obfs) == list:
            password = password_obfs[0]
            obfs = common.to_str(password_obfs[1])
            if len(password_obfs) > 2:
                protocol = common.to_str(password_obfs[2])
        # 若password_obfs 是dict
        # 依次获取 密码、加密方式、混淆、混淆参数、协议、协议参数、bind、bindv6
        elif type(password_obfs) == dict:
            password = password_obfs.get('password', config_password)
            method = common.to_str(password_obfs.get('method', method))
            protocol = common.to_str(password_obfs.get('protocol', protocol))
            protocol_param = common.to_str(password_obfs.get('protocol_param', protocol_param))
            obfs = common.to_str(password_obfs.get('obfs', obfs))
            obfs_param = common.to_str(password_obfs.get('obfs_param', obfs_param))
            bind = password_obfs.get('out_bind', bind)
            bindv6 = password_obfs.get('out_bindv6', bindv6)
        # 其他情况
        # password = password_obfs
        else:
            password = password_obfs
        # a_config 对 config 浅 copy
        a_config = config.copy()
        # ipv6_ok 设置为false
        ipv6_ok = False
        logging.info("server start with protocol[%s] password [%s] method [%s] obfs [%s] obfs_param [%s]" %
                (protocol, password, method, obfs, obfs_param))
        # ipv6 设置
        if 'server_ipv6' in a_config:
            try:
                if len(a_config['server_ipv6']) > 2 and a_config['server_ipv6'][0] == "[" and a_config['server_ipv6'][-1] == "]":
                    a_config['server_ipv6'] = a_config['server_ipv6'][1:-1]
                a_config['server_port'] = int(port)
                a_config['password'] = password
                a_config['method'] = method
                a_config['protocol'] = protocol
                a_config['protocol_param'] = protocol_param
                a_config['obfs'] = obfs
                a_config['obfs_param'] = obfs_param
                a_config['out_bind'] = bind
                a_config['out_bindv6'] = bindv6
                a_config['server'] = a_config['server_ipv6']
                logging.info("starting server at [%s]:%d" %
                             (a_config['server'], int(port)))
                tcp_servers.append(tcprelay.TCPRelay(a_config, dns_resolver, False, stat_counter=stat_counter_dict))
                udp_servers.append(udprelay.UDPRelay(a_config, dns_resolver, False, stat_counter=stat_counter_dict))
                if a_config['server_ipv6'] == b"::":
                    ipv6_ok = True
            except Exception as e:
                shell.print_exception(e)

        try:
            # 获取配置信息
            a_config = config.copy()
            a_config['server_port'] = int(port)
            a_config['password'] = password
            a_config['method'] = method
            a_config['protocol'] = protocol
            a_config['protocol_param'] = protocol_param
            a_config['obfs'] = obfs
            a_config['obfs_param'] = obfs_param
            a_config['out_bind'] = bind
            a_config['out_bindv6'] = bindv6
            logging.info("starting server at %s:%d" %
                         (a_config['server'], int(port)))

            tcp_servers.append(tcprelay.TCPRelay(a_config, dns_resolver, False, stat_counter=stat_counter_dict))
            udp_servers.append(udprelay.UDPRelay(a_config, dns_resolver, False, stat_counter=stat_counter_dict))
        except Exception as e:
            if not ipv6_ok:
                shell.print_exception(e)

    def run_server():
        # 收到 signal.SIGTERM 信号时关闭线程
        def child_handler(signum, _):
            logging.warn('received SIGQUIT, doing graceful shutting down..')
            list(map(lambda s: s.close(next_tick=True),
                     tcp_servers + udp_servers))
        # 获取默认信号 并设置 handler
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM),
                      child_handler)

        def int_handler(signum, _):
            sys.exit(1)
        signal.signal(signal.SIGINT, int_handler)

        try:
            # 初始化 loop
            loop = eventloop.EventLoop()
            # dns_resolver 绑定 loop
            dns_resolver.add_to_loop(loop)
            # 遍历 servers 绑定loop
            list(map(lambda s: s.add_to_loop(loop), tcp_servers + udp_servers))
            # 设置用户 若不存在 则 None
            daemon.set_user(config.get('user', None))
            # 运行 loop
            loop.run()
        except Exception as e:
            shell.print_exception(e)
            sys.exit(1)
    # 判断 workers 的数量
    if int(config['workers']) > 1:
        # 当 workers 大于 1 且 系统为 linux 的时候
        if os.name == 'posix':
            # 初始化 children 存放线程 pid
            children = []
            # 设置 is_child 为false
            is_child = False
            # 循环
            for i in range(0, int(config['workers'])):
                # 创建一个新线程
                r = os.fork()
                if r == 0:
                    logging.info('worker started')
                    is_child = True
                    run_server()
                    break
                else:
                    children.append(r)
            # 若不是子线程
            if not is_child:
                def handler(signum, _):
                    for pid in children:
                        try:
                            # os.kill(pid, sig)
                            # 向进程pid发送信号sig。可用的sig在signal模块中定义。
                            os.kill(pid, signum)
                            # 等待指定pid（大于0）的子进程结束，返回一个元组，包含pid和退出码。参数options一般情况下应为0。
                            os.waitpid(pid, 0)
                        except OSError:  # child may already exited
                            pass
                    sys.exit()
                # 关闭线程
                signal.signal(signal.SIGTERM, handler)
                signal.signal(signal.SIGQUIT, handler)
                signal.signal(signal.SIGINT, handler)

                # 关闭server
                # master
                for a_tcp_server in tcp_servers:
                    a_tcp_server.close()
                for a_udp_server in udp_servers:
                    a_udp_server.close()
                dns_resolver.close()

                # 关闭子进程
                for child in children:
                    os.waitpid(child, 0)
        else:
            logging.warn('worker is only available on Unix/Linux')
            run_server()
    else:
        run_server()


if __name__ == '__main__':
    main()
