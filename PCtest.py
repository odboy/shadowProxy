#!/usr/vin/env python3
# -*- coding: utf-8 -*-


import ProxyCoordinator

pc = ProxyCoordinator.ProxyCoordinator(multipletimes=2)
pc.importPorxies("../../pythonCode/kuaidaili_list.txt")

target1 = ("10.1.1.1", 80)
target2 = ("20.2.2.2", 8080)

print("\t\t\ttarget1")
while True:
    proxy = pc.dispatchProxy(target1)
    if proxy:
        print(proxy)
    else:
        print('无可用Proxy')
        break

print("\t\t\ttarget2")
while True:
    proxy = pc.dispatchProxy(target2)
    if proxy:
        print(proxy)
    else:
        print('无可用Proxy')
        break
