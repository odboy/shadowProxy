#!/usr/vin/env python3
# -*- coding: utf-8 -*-

# 参考资料http://docs.ganeti.org/ganeti/2.14/html/design-x509-ca.html
__author__ = "Mr.Bingo"
__version__ = "0.1"

import time
import os
import OpenSSL
import sys

class CertsTool(object):
    def __init__(self):
        pass

    @classmethod
    def create_pk(cls):
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        return key
    @classmethod
    def create_ca(cls):
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(int(time.time() * 10000))
        cert.get_subject().CN = "shadowProxy CA"
        cert.get_subject().O = "ODBOY"
        cert.gmtime_adj_notBefore(-3600 * 48)
        cert.gmtime_adj_notAfter(60*60*24*365*3)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.add_extensions([
            OpenSSL.crypto.X509Extension(
                b"basicConstraints",
                True,
                b"CA:TRUE"
            ),
            OpenSSL.crypto.X509Extension(
                b"nsCertType",
                False,
                b"sslCA"
            ),
            OpenSSL.crypto.X509Extension(
                b"extendedKeyUsage",
                False,
                b"serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC"
            ),
            OpenSSL.crypto.X509Extension(
                b"keyUsage",
                True,
                b"keyCertSign, cRLSign"
            ),
            OpenSSL.crypto.X509Extension(
                b"subjectKeyIdentifier",
                False,
                b"hash",
                subject=cert
            ),
        ])
        cert.sign(key, "sha256")
        return key, cert

    @classmethod
    def load_ca(cls,cacert,cakey):
        with open(cacert,"r") as f:
            raw = f.read()
            cacert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,raw)

        with open(cakey, "r") as f:
            raw = f.read()
            cakey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,raw)
        return cacert,cakey

    # p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
    @classmethod
    def create_csr(cls,certkey,hostname):

        with open(certkey,"r") as f:
            raw = f.read()

        key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,raw)

        # key = OpenSSL.crypto.PKey()
        # key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        req = OpenSSL.crypto.X509Req()
        req.get_subject().CN = hostname
        req.set_pubkey(key)
        req.sign(key, "sha256")

        # Write private key
        # print(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key).decode())

        # Write request
        # print(OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req).decode())
        return req

    @classmethod
    def certificate_csr(cls,cacert,cakey,csreq):

        cert = OpenSSL.crypto.X509()
        cert.set_version(2) # 不能为3
        cert.set_subject(csreq.get_subject())
        cert.set_serial_number(int(time.time() * 10000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(24 * 60 * 60)
        cert.set_issuer(cacert.get_subject())
        cert.set_pubkey(csreq.get_pubkey())
        cert.sign(cakey, "sha256")

        # print(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode())
        return cert

if __name__ == "__main__":
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)),"certs")
    basename = "shadowproxy"

    if len(sys.argv)>1 and sys.argv[1].upper() == "CREATECA":
        if not os.path.exists(path):
            os.makedirs(path)
        key, ca = CertsTool.create_ca()
        with open(os.path.join(path, basename+"CA.crt"), "wb") as f:
            f.write(
                OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    ca))
        print("生成CA根证书："+os.path.join(path, basename+"CA.crt"))
        with open(os.path.join(path, basename+"CA.key"), "wb") as f:
            f.write(
            OpenSSL.crypto.dump_privatekey(
                OpenSSL.crypto.FILETYPE_PEM,
                key))
        print("根证书私钥：" + os.path.join(path, basename+"CA.key"))

        key = CertsTool.create_pk()
        with open(os.path.join(path, "cert.key"), "wb") as f:
            f.write(
            OpenSSL.crypto.dump_privatekey(
                OpenSSL.crypto.FILETYPE_PEM,
                key))
        print("Proxy私钥：" + os.path.join(path, "cert.key"))


    if (not os.path.exists(os.path.join(path, basename+"CA.crt"))) \
            or (not os.path.exists(os.path.join(path, basename+"CA.key")))\
            or (not os.path.exists(os.path.join(path, "cert.key"))):
        print("\n缺少证书 - 执行如下命令生成所需证书\n\n\t\x1b[32mpython3 certs.py CREATECA\x1b[0m")
        time.sleep(0.1)
        sys.exit(0)
    ca,key = CertsTool.load_ca(os.path.join(path, basename+"CA.crt"),os.path.join(path, basename+"CA.key"))

    csreq = CertsTool.create_csr(os.path.join(path, "cert.key"),"oddboy.cn")
    testcrt = CertsTool.certificate_csr(ca,key,csreq)

    if not os.path.exists(os.path.join(path,"sites")):
        os.makedirs(os.path.join(path,"sites"))
    with open(os.path.join(path,"sites" ,"testcert.crt"), "wb") as f:
        f.write(
        OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            testcrt))

    print("生成测试站点证书："+ os.path.join(path,"sites" ,"testcert.crt"))
    print()
    print(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            testcrt).decode())