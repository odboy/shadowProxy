# shadowProxy


## 使用方法

- 查看帮助
```bash
 python3 shadowProxy.py -h
        .--.
       |o_o |    ------------------
       |:_/ |   < Author: Mr.Bingo >
      //   \ \   ------------------
     (|     | ) <    oddboy.cn     >
    /'\_   _/`\  ------------------
    \___)=(___/

usage: shadowProxy.py [-h] [--bind BIND] [--port PORT]
                      [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                      [--proxyListFile PROXYLISTFILE] [-t MULTIPLETIMES]

optional arguments:
  -h, --help            show this help message and exit
  --bind BIND           Default: 127.0.0.1
  --port PORT           Default: 8088
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Default: WARNING
  --proxyListFile PROXYLISTFILE
                        代理列表文件
  -t MULTIPLETIMES      单一代理可被使用的次数,默认为2^31-1
```

- 运行
```bash
python3 shadowProxy.py --proxyListFile proxylist.txt
        .--.
       |o_o |    ------------------
       |:_/ |   < Author: Mr.Bingo >
      //   \ \   ------------------
     (|     | ) <    oddboy.cn     >
    /'\_   _/`\  ------------------
    \___)=(___/

初始化代理池  本地IP :: 111.199.186.1
导入代理池:::	proxylist.txt
成功导入 55 个代理
Serving HTTP on 127.0.0.1 port 8088 (http://127.0.0.1:8088/) ...
```

- 安装SSL证书(访问HTTPS需要)

【方式一】

Unix-Like系统下，直接运行`setup_https_intercept.sh`生成证书。
```bash
./setup_https_intercept.sh
Generating RSA private key, 2048 bit long modulus
........................................................+++
.........+++
e is 65537 (0x10001)
Generating RSA private key, 2048 bit long modulus
....................................................................+++
..+++
e is 65537 (0x10001)
```
【方式二】
*nix及windows主机均可使用。 
```bash
$ python3 certs.py CREATECA
生成CA根证书：shadowProxy/certs/shadowproxyCA.crt
根证书私钥：shadowProxy/certs/shadowproxyCA.key
Proxy私钥：shadowProxy/certs/cert.key
生成测试站点证书：shadowProxy/certs/sites/testcert.crt
```

然后在代理到端口的浏览器中访问[http://shadow.proxy/](http://shadow.proxy/) 即可下载，导入系统/浏览器即可。

## todo list
- 运行过程中动态更新代理库

- 明确打一枪换一炮模式与幽灵模式

- 幽灵模式下动态评估代理质量，并进行优化选择

- 完善日志记录