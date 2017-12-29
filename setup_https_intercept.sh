#!/bin/sh
mkdir -p certs/sites/    # 网站证书目录，
openssl genrsa -out certs/ca.key 2048     # CA私钥
openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt -subj "/CN=shadowProxy CA"    # CA公钥自签名根证书
openssl genrsa -out certs/cert.key 2048   # 服务器私钥

