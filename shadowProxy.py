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
import requests
from urllib.parse import urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from subprocess import Popen, PIPE


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

# 管理代理池
class ProxyCoordinator(object):
    def __init__(self):
        self.ipViewURL = "http://api.ipify.org"
        self.localPublicIP = self.getPublicIP()


    def getPublicIP(self, proxy=None):
        if proxy is None:   # 获取本地IP
            r = requests.get(self.ipViewURL, timeout=15)
            return r.text
        else:
            try:
                proxy = re.match(r"^https?://(\d{1,3}[\.:]){4}\d+$", proxy.lower().replace(' ', '')).group()
                r = requests.get(self.ipViewURL, proxies={proxy.split("://")[0]: proxy}, verify=False, timeout=15)
                logging.info("返回数据:%s" % r.text.replace(' ', '')[:300])
                ip = re.match(r"((\d{1,3}\.){3}\d{1,3})", r.text.replace(' ', '')).group()
                logging.info(" IP :%s" % ip)
                return ip
            except:
                return None

    def verifyProxy(self,proxy):
        currentIP = self.getPublicIP(proxy)
        if (currentIP != self.localPublicIP) and (currentIP is not None):
            return currentIP
        else:
            return None

    def dispatchProxy(self,target):   # 为某个目标主机分配代理
        pass
        return "http://127.0.0.1:8080"


class shadowProxyRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.cakey = Utility.getAbsPath('certs/ca.key')  # CA私钥
        self.cacert = Utility.getAbsPath('certs/ca.crt')  # CA公钥自签名根证书
        self.certkey = Utility.getAbsPath('certs/cert.key')  # 服务器私钥
        self.certdir = Utility.getAbsPath('certs/sites/')  # 站点证书
        self.timeout = 10  # todo timeout原本为5,调整为300以便进行调试。
        self.threadLock = threading.Lock()
        self.tls        =   threading.local()   # 线程局部变量 Thread Local Storage
        self.tls.conns  =   {}
        self.pc = ProxyCoordinator()
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            # 提示证书安装
            print(Utility.colorRender(31, "服务器缺少证书，请在程序目录生成证书"))
            self.send_error(502,"Server lack of certificate")
            # 错误代码 https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
            return

    def connect_intercept(self):
        if self.path[0] == "/":
            self.send_response_only(599, 'HEY, WHAT FUCK YOU WANNA DO?')
            self.end_headers()
            return
        hostname = self.path.split(':')[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.threadLock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                # 生成证书请求
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                # 使用CA的私钥对证书请求文件进行签名，生成证书。
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

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

        # todo 为什么需要替换为完整URL路径？
        # https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
        # The absoluteURI form is REQUIRED when the request is being made to a proxy. The proxy is requested to forward the request or service it from a valid cache, and return the response. Note that the proxy MAY forward the request on to another proxy or directly to the server specified by the absoluteURI. In order to avoid request loops, a proxy MUST be able to recognize all of its server names, including any aliases, local variations, and the numeric IP address.
        # print(req.path)
        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket): # ssl.SSLSocket or ssl.SSLContext
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)
        # print("处理后path:"+req.path)
        u = urlparse(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ("http", "https")
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))
        # if 1:
        try:
            target = (scheme, netloc)

            # 输入URL的协议和主机，返回可用的连接HTTP(S)Connection
            proxy = self.pc.dispatchProxy(target)
            proxy = "http://127.0.0.1:8080" # todo 暂时先固定为http://127.0.0.1:8080
            # conn = http.client.HTTPSConnection("localhost", 8080)
            # conn.set_tunnel("www.python.org")
            # conn.request("HEAD", "/index.html")

            if proxy.split("://")[0] == "http":
                conn = http.client.HTTPConnection(proxy.split("://")[1], timeout=self.timeout)
            elif proxy.split("://")[0] == "https":
                conn = http.client.HTTPSConnection(proxy.split("://")[1], timeout=self.timeout)
            if target not in self.tls.conns:
                self.tls.conns[target] = conn.set_tunnel(netloc)        # todo 此处存在逻辑问题，急需梳理！ 这句代理可以省略，但需要在request命令中带全URL地址。

            # if target not in self.tls.conns:
            #
            #     # TODO [核心功能点]代理管理点
            #     if scheme == 'https':
            #         self.tls.conns[target] = http.client.HTTPSConnection(netloc, timeout=self.timeout)
            #     else:
            #         self.tls.conns[target] = http.client.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[target]
            conn.request(self.command, path, req_body, dict(self.headers))
            res = conn.getresponse()
            res.response_version = 'HTTP/1.1' if res.version == 11 else 'HTTP/1.0'

            # support streaming / Translate-encoding  chunked
            if 'Content-Length' not in res.headers and 'chunked' in res.headers.get('Transfer-Encoding', ''):
                with self.threadLock:
                    print(req.headers)
                    print(Utility.colorRender(33,"chunked\t"+self.path))
                    print(res.headers)
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)   # 转发chunked包
                # with self.threadLock:
                #     self.save_handler(req, req_body, res, '')
                return

            res_body = res.read() # 非chunked数据包
        # try:
        #     pass
        except Exception as e:
            logging.debug(e)
            if target in self.tls.conns:
                del self.tls.conns[target]
            self.send_error(502)
            return
        # 继续处理非chunked的情况
        print(Utility.colorRender(34, "非chunked\t" + self.path))
        setattr(res, 'headers', self.filter_headers(res.headers))
        # print(res.headers)
        self.send_response_only(res.status, res.reason)
        for keyword in res.headers:
            # print(keyword +": "+ res.headers.get(keyword, "") )
            self.send_header(keyword, res.headers.get(keyword, ""))
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()


    # 转发chunked数据包，但没法检测发包结束（即 last-chunk ）
    def relay_streaming(self, res):
        self.send_response_only(res.status, res.reason)
        # self.wfile.write(b"%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for keyword in res.headers:
            self.send_header(keyword, res.headers.get(keyword, ""))
        self.end_headers()
        try:
            while True:
                # print "res.read前" + str(time.time())
                chunk = res.read(4096)  # 经测算，该方法为阻塞性的。
                # print "res.read后" + str(time.time())
                # todo 如何检测last-chunk？

                if not chunk:  # this code is useless
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_TRACE = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        hop_by_hop = ()
        for k in hop_by_hop:
            del headers[k]

        if "Transfer-Encoding" in headers:
             del headers["Transfer-Encoding"]
        if  headers['Connection'] == "keep-alive":
            del headers['Connection']
            headers['Connection'] = 'close'

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

    # 修改request内容
    def request_handler(self, req, req_body):
        pass

    # 修改response内容
    def response_handler(self, req, req_body, res, res_body):
        pass

    # 保持交互内容
    def save_handler(self, req, req_body, res, res_body):
        pass

def run(HandlerClass=BaseHTTPRequestHandler,
         ServerClass=HTTPServer, protocol="HTTP/1.1", port=8088, bind=""):
    server_address = (bind, port)

    HandlerClass.protocol_version = protocol
    with ServerClass(server_address, HandlerClass) as httpd:
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
                "       |:_/ |   < Author: Mr.Bingo >\n" \
                "      //   \ \   ------------------ \n" \
                "     (|     | ) <    oddboy.cn     >\n" \
                "    /'\_   _/`\  ------------------\n" \
                "    \___)=(___/\n"
    print(headCharPic)
    # Creating a parser
    parser = argparse.ArgumentParser()

    parser.add_argument('--bind', dest="bind",default='0.0.0.0', help='Default: 0.0.0.0')
    parser.add_argument('--port', dest='port',type=int,default='8088', help='Default: 8088')
    parser.add_argument('--log-level', default='INFO', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'), help='Default: INFO')

    parser.add_argument('--testcode', action='store_true', default = False,help="测试使用" )
    # todo 添加代理池相关配置及分配原则等。。。

    args = parser.parse_args()
    if args.testcode:
        test()
        sys.exit(0)
    logging.basicConfig(level=getattr(logging, args.log_level), format='%(asctime)s - %(levelname)s - pid:%(process)d - %(message)s')

    run(ServerClass=ThreadingHTTPServer,HandlerClass=shadowProxyRequestHandler,port=args.port,bind=args.bind)

if __name__ == '__main__':
    main()
