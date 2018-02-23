#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import threading
import logging
import argparse
import time
import socket
import ssl
import re
import http.client
from urllib.parse import urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from subprocess import Popen, PIPE
from ProxyCoordinator import ProxyCoordinator
import OpenSSL
from certs import CertsTool

proxyCoor = ProxyCoordinator()


class Utility(object):
    @staticmethod
    def colorRender(c,s):
        try:
            return "\x1b[%dm%s\x1b[0m" % (c, s)
        except:
            return s

    @staticmethod
    def getAbsPath(path):
        try:
            return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
        except:
            return None

def test():
    pass
    print("<<<常用颜色输出>>>")
    for i in range(6):
        print(Utility.colorRender(i+31,i+31)+"\t",end="")
    print()
    for i in range(6):
        print(Utility.colorRender(i+41,i+41)+"\t",end="")
    print()


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True
    # The entire Python program exits when no alive non-daemon threads are left.
    # 也就是说设置为daemon的线程会随着主线程的退出而结束，而非daemon线程会阻塞主线程的退出。

    def handle_error(self, request, client_address):
        # 屏蔽 socket/ssl 相关错误
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)

class shadowProxyRequestHandler(BaseHTTPRequestHandler):
    global proxyCoor
    def __init__(self, *args, **kwargs):
        # self.cakey = Utility.getAbsPath('certs/shadowproxyCA.key')  # CA私钥
        # self.cacert = Utility.getAbsPath('certs/shadowproxyCA.crt')  # CA公钥自签名根证书
        # self.certkey = Utility.getAbsPath('certs/cert.key')  # 服务器私钥
        # self.certdir = Utility.getAbsPath('certs/sites/')  # 站点证书
        self.cakey = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs','shadowproxyCA.key')  # CA私钥
        self.cacert = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs','shadowproxyCA.crt') # CA公钥自签名根证书
        self.certkey = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs','cert.key')         # 服务器私钥
        self.certdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs','sites')            # 站点证书
        self.timeout = 15  # up-steaming timeout时间
        self.threadLock = threading.Lock()
        self.tls        =   threading.local()   # 线程局部变量 Thread Local Storage
        self.tls.conns  =   {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            # 提示证书安装
            print(Utility.colorRender(31, "服务器缺少证书，请在程序目录生成证书\t\x1b[32mpython3 certs.py CREATECA\x1b[0m"))
            self.send_error(502,"Server lack of certificate")
            # 错误代码 https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
            return

    def connect_intercept(self):
        if self.path[0] == "/":
            self.send_response_only(599, 'HEY, WHAT FUCK YOU WANNA DO?  Just Kidding...')
            self.end_headers()
            return
        hostname = self.path.split(':')[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.threadLock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                # 生成证书请求
                # p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                csreq = CertsTool.create_csr(self.certkey, hostname)
                # 使用CA的私钥对证书请求文件进行签名，生成证书。
                # p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                # p2.communicate()
                ca, key = CertsTool.load_ca(self.cacert,self.cakey)
                sitecrt = CertsTool.certificate_csr(ca, key, csreq)

                with open(os.path.join(self.certdir, "%s.crt"%hostname), "wb") as f:
                    f.write(
                        OpenSSL.crypto.dump_certificate(
                            OpenSSL.crypto.FILETYPE_PEM,
                            sitecrt))


        self.send_response_only(200, 'Connection Established')
        self.end_headers()

        sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLS)
        # ssl.PROTOCOL_SSLv23
        # Alias for data:PROTOCOL_TLS.
        # Deprecated since version 3.6: Use PROTOCOL_TLS instead.
        # print("certpath :: "+certpath)
        # print("存在") if os.path.exists(certpath) else print("死哪去了")
        # print("keyfile  :: "+self.certkey)
        sslcontext.load_cert_chain(certpath, keyfile=self.certkey)  # 证书(客户端) & 私钥(服务端)
        self.connection = sslcontext.wrap_socket(self.connection, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        # todo 什么情况下会有Proxy-Connection
        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def do_GET(self):

        if self.path == 'http://shadow.proxy/':
            self.send_cacert()
            # print("%s download %s" % (self.client_address, self.cacert))
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket): # ssl.SSLSocket or ssl.SSLContext
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        u = urlparse(req.path)
        scheme, netloc= u.scheme, u.netloc
        assert scheme in ("http", "https")
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        retryFlag = 0
        while retryFlag < 10 :
            if 1:
                target = (scheme, netloc)
                # 输入URL的协议和主机，返回可用的连接HTTP(S)Connection
                proxy = proxyCoor.dispatchProxy(target)
                if proxy is None:
                    print("未能获取到可用Proxy...(可能是Proxy耗尽...)")
                    self.send_error(502,"proxy resource RUN OUT!!!")
                    return
                print("%s --> [ %d ] %s" % (proxy, retryFlag + 1, req.path))

                if proxy.split("://")[0] == "http":
                    conn = http.client.HTTPConnection(proxy.split("://")[1], timeout=self.timeout)
                elif proxy.split("://")[0] == "https":
                    conn = http.client.HTTPSConnection(proxy.split("://")[1], timeout=self.timeout)

                conn.request(self.command, req.path, req_body, dict(req.headers))
                res = conn.getresponse()
                # res.response_version = 'HTTP/1.1' if res.version == 11 else 'HTTP/1.0'
                res_body = res.read()       # Transfer-Encoding并不需要特殊处理(除了Content-Length外)
            try:
                pass
            except Exception as e:
                retryFlag += 1
                # self.send_error(502)
                # return
            else:
                try:
                    if 'Content-Length' not in res.headers:
                        res.headers['Content-Length'] = str(len(res_body))
                    setattr(res, 'headers', self.filter_headers(res.headers))
                    self.send_response_only(res.status, res.reason)
                    for keyword in res.headers:
                        self.send_header(keyword, res.headers.get(keyword, ""))
                    self.end_headers()
                    self.wfile.write(res_body)
                    self.wfile.flush()
                except:
                    pass
                finally:
                    retryFlag = 9999  # 极大值，结束重试。
                    conn.close()

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_TRACE = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('Connection', 'Keep_Alive', 'Proxy-Authenticate', 'Proxy-Authorization', 'TE', 'Trailers', 'Transfer-Encoding', 'Upgrade')
        #hop_by_hop = ()
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    # 发送证书
    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.send_response(200,'OK')
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

def run(HandlerClass=BaseHTTPRequestHandler,
         ServerClass=HTTPServer, protocol="HTTP/1.1", port=8088, bind=""):
    server_address = (bind, port)

    HandlerClass.protocol_version = protocol
    #with ServerClass(server_address, HandlerClass) as httpd:    # fix bug :: AttributeError: __exit__
    httpd = ServerClass(server_address, HandlerClass)
    sa = httpd.socket.getsockname()
    serve_message = "Serving HTTP on {host} port {port} (http://{host}:{port}/) ..."
    print(serve_message.format(host=sa[0], port=sa[1]))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received, exiting.")
        sys.exit(0)

def main():
    headCharPic="\r        .--.\n" \
                "       |o_o |    ------------------ \n" \
                "       |:_/ |   <   猎户攻防实验室   >\n" \
                "      //   \ \   ------------------ \n" \
                "     (|     | ) < liehu.tass.com.cn >\n" \
                "    /'\_   _/`\  ------------------\n" \
                "    \___)=(___/\n"
    print(headCharPic)
    # Creating a parser
    parser = argparse.ArgumentParser()

    parser.add_argument('--bind', dest="bind",default='127.0.0.1', help='Default: 127.0.0.1')
    parser.add_argument('--port', dest='port',type=int,default='8088', help='Default: 8088')
    parser.add_argument('--log-level', default='CRITICAL', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'), help='Default: CRITICAL')
    parser.add_argument('--proxyListFile',default="proxylist.txt", dest='proxyListFile', required=False, help='代理列表文件')

    parser.add_argument('-t',dest="multipletimes", default=2147483647,type=int,help='单一代理可被使用的次数,默认为2^31-1')

    args = parser.parse_args()
    proxyCoor._setAvailableTimes(args.multipletimes)
    proxyCoor.importPorxies(args.proxyListFile)

    logging.basicConfig(level=getattr(logging, args.log_level), format='%(asctime)s - %(levelname)s - pid:%(process)d - %(message)s')

    run(ServerClass=ThreadingHTTPServer,HandlerClass=shadowProxyRequestHandler,port=args.port,bind=args.bind)

if __name__ == '__main__':
    main()
