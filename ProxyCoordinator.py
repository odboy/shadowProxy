#!/usr/vin/env python3
# -*- coding: utf-8 -*-

' this module used to manage proxies'

__author__ = "Mr.Bingo"
__version__ = "0.1"

import requests
import re
import os
import threading
import queue
import time
import random
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 1 导入Proxy列表       # 文件导入
# 2 处理策略：
#   2.1 限定代理的使用次数
#   2.2 对单一目标(ip:port)限定代理的使用次数
#   2.3 指定判断条件：指定方法(GET或HEAD）访问目标某URL，得到200反应。

# 管理代理池
class ProxyCoordinator(object):

    def __init__(self, multipletimes=1):
        self.ipViewURL = "http://api.ipify.org"
        self.localPublicIP = self.getPublicIP()
        self.proxyDict = {}
        self.availableTimes = multipletimes if multipletimes > 0 else 1     # 每个代理可被使用的次数
        self.rawProxyList = queue.Queue()
        self.proxyDictUsage = {}     # 每个目标作为一个key,value为各自的一个proxyDict。
        self.threadLock = threading.Lock()
        self.usableCount = 0

    def _setAvailableTimes(self,multipletimes):
        self.availableTimes = multipletimes if multipletimes > 0 else 1  # 每个代理可被使用的次数
        return

    def conditionFunc(self,proxy):
        """重写该方法，从而引入条件判断，在这种情况下，multipletimes仍然生效，故而建议设置为一个较大值"""
        return True

    def importPorxies(self,proxyListFile):
        """导入Proxy列表文件,一行一个proxy:
        http://127.0.0.1:8080
        https://10.20.30.40:999
        """
        print("初始化代理池  本地IP :: " + self.localPublicIP)
        print("导入代理池:::\t%s"%proxyListFile)
        with open(proxyListFile,'r') as f:
            for line in f.readlines():
                try:
                    proxy = re.match(r"^https?://(\d{1,3}[\.:]){4}\d+$", line.lower()).group()
                    self.rawProxyList.put(proxy)
                except:
                    pass
        thread_arr = []
        for i in range(min(self.rawProxyList.qsize(), 100)):      # 多线程进行代理可用性及匿名性验证
            t = threading.Thread(target=self.__verifyAndImportProxy)
            t.daemon=True
            thread_arr.append(t)
        for t in thread_arr:
            t.start()
        for t in thread_arr:
            t.join()
        print(" \b\b" * 50,end="")
        print("成功导入 %d 个代理"%self.usableCount)
        # with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".list"),"w",encoding="utf-8") as f:
        #     for key, value in self.proxyDict.items():
        #         if int(value) > 0:
        #             f.write(key+"\n")

    def getPublicIP(self, proxy=None):
        """获取通过Proxy上网的公网IP地址，若Proxy为None，则获取本地主机的公网IP"""
        if proxy is None:   # 获取本地IP
            r = requests.get(self.ipViewURL, timeout=15)
            return r.text
        else:
            try:
                proxy = re.match(r"^https?://(\d{1,3}[\.:]){4}\d+$", proxy.lower().replace(' ', '')).group()
                r = requests.get(self.ipViewURL, proxies={proxy.split("://")[0]: proxy}, verify=False, timeout=15)
                # logging.info("返回数据:%s" % r.text.replace(' ', '')[:300])
                ip = re.match(r"((\d{1,3}\.){3}\d{1,3})", r.text.replace(' ', '')).group()
                # logging.info(" IP :%s" % ip)
                return ip
            except:
                return None

    def __verifyAndImportProxy(self):
        while not self.rawProxyList.empty():
            proxy = self.rawProxyList.get()
            if self.proxyDict.get(proxy) is None:   # 判断是否已经读取(proxy列表可能存在重复)
                currentIP = self.getPublicIP(proxy)
                if (currentIP != self.localPublicIP) and (currentIP is not None):
                    self.proxyDict[proxy] = self.availableTimes
                    with self.threadLock:
                        self.usableCount += 1
                        print(" \b\b" * 50, end="")
                        print("\r%s 可用\t已导入数量: %d"%(proxy,self.usableCount),end="")
                else:
                    self.proxyDict[proxy] = 0

    def dispatchProxy(self, target=None):
        """为某个目标主机分配代理"""
        if target is None:
            target = "DefaultTarget"

        if target not in self.proxyDictUsage: # 针对该target进行代理字典的初始化
            dict = {}
            for item in self.proxyDict:
                if self.proxyDict[item] > 0:
                    dict[item] = self.proxyDict[item]
            self.proxyDictUsage[target] = dict
            if len(dict) <= 0:
                return None

        tempFlag = True
        while tempFlag:
            if self.proxyDictUsage[target] == 0:
                return None

            proxy,availabletime = random.choice(list(self.proxyDictUsage[target].items()))
            if availabletime > 0:
                try:
                    if self.conditionFunc(proxy):
                        tempFlag = False
                        self.proxyDictUsage[target][proxy] -= 1
                        return proxy
                    else:
                        pass
                except Exception as e:
                    print(e)
            else:
                self.proxyDictUsage[target].pop(proxy)  # 从dict中清除耗尽的Proxy
        return None

class myProxyCoor(ProxyCoordinator):
    def conditionFunc(self,proxy):
        print("条件判断：：%s"%proxy)
        r = requests.get("http://aws.oddboy.cn/1.txt", proxies={proxy.split("://")[0]: proxy}, verify=False, timeout=15)
        if r.status_code== 200:
            return True
        return False

if __name__=="__main__":

    pc = myProxyCoor(multipletimes=2)
    pc.importPorxies("proxylist.txt")
    while True:
        print(pc.dispatchProxy())

        time.sleep(1)


    # pc = ProxyCoordinator(multipletimes=2)
    # pc.importPorxies("../../pythonCode/kuaidaili_list.txt")
    #
    # target1 = ("10.1.1.1", 80)
    # target2 = ("20.2.2.2", 8080)
    #
    # print("\t\t\ttarget1")
    # while True:
    #     proxy = pc.dispatchProxy(target1)
    #     if proxy:
    #         print(proxy)
    #     else:
    #         print('无可用Proxy')
    #         break
    #
    # print("\t\t\ttarget2")
    # while True:
    #     proxy = pc.dispatchProxy(target2)
    #     if proxy:
    #         print(proxy)
    #     else:
    #         print('无可用Proxy')
    #         break

