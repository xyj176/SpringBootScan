#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Author：BetterDefender
Version：1.0.3
Github：https://github.com/BetterDefender

For Example:
将需要测试的URL放入url.txt中，格式如下：
https://www.example.com
https://www.test.com

运行
python3 SpringBootScan.py

测试报告在result/目录下，报告命名为：url列表中第一个url的 域名 加 时分秒

边学边写，所以所有的注释就不删除了
'''
from pathlib import Path

import dominate
from dominate.tags import *
import requests
import sys, os
import threading  # 引入多线程
import time


##为url传递参数
# url_params = {'q':'python'}    #字典传递参数，如果值为None的键不会被添加到URL中
# r = requests.get('https://www.baidu.com',params=url_params)
# r.encoding = 'utf-8'
# print(r.url)
# print(r.text)

def run():
    print(
        '  ____             _               ____              _     ____\n'
        ' / ___| _ __  _ __(_)_ __   __ _  | __ )  ___   ___ | |_  / ___|  ___ __ _ _ __\n'
        " \___ \| '_ \| '__| | '_ \ / _` | |  _ \ / _ \ / _ \| __| \___ \ / __/ _` | '_  |\n"
        '  ___) | |_) | |  | | | | | (_| | | |_) | (_) | (_) | |_   ___) | (_| (_| | | | |\n'
        ' |____/| .__/|_|  |_|_| |_|\__, | |____/ \___/ \___/ \__| |____/ \___\__,_|_| |_|\n'
        '       |_|                 |___/\n'
        '                                                                                  \n'
        '                                        Version:1.0.3\n'
        '                                        Author：BetterDefender\n'
        '                                        Github：https://github.com/BetterDefender\n'
        '                                                                                   \n'
        '测试中，请耐心等待...\n'
    )
    time.sleep(1)


def report_create(suffix: str):
    """
    生成报告路径
    :param suffix: 报告格式，如‘txt’,'html'
    :return:
    """
    now = int(time.time())  # 获取时间戳
    time_array = time.localtime(now)  # 格式化时间戳为本地的时间
    other_style_time = time.strftime("%H%M%S", time_array)  # 格式化时间，获取时分秒
    report_path = 'result/' + other_style_time + '_report.' + suffix  # 获取文本第一行域名，并且添加时分秒为报告名字
    return report_path


def get_rule(r):
    url = r.url
    content = None
    global count
    # 判断报告中是否已存在该URL
    if "OSS" in r.text:
        count += 1
        content = '[%s] ' % r.status_code + url + ' 疑似存在阿里云OSS密钥信息泄漏，请自行确认'
        txt_report_file.write(content + '\n')
        with doc:
            a(content, href=url, target='_blank')
            br()
    if 'title="%s"' % url in r.text:
        count += 1
        content = '[%s] ' % r.status_code + url + ' 疑似存在springboot信息泄漏，请自行确认'
        txt_report_file.write(content + '\n')
        with doc:
            a(content, href=url, target='_blank')
            br()
    if r.status_code == 200:
        count += 1
        # 200的都是未鉴权的
        content = '[%s] ' % r.status_code + url + ' 未鉴权，请自行确认'
        txt_report_file.write(content + '\n')
        with doc:
            a(content, href=url, target='_blank')
            br()
        if "swagger" in r.url:
            count += 1
            content = '[%s] ' % r.status_code + url + ' 疑似存在springboot信息泄漏，请自行确认'
            txt_report_file.write(content + '\n')
            with doc:
                a(content, href=url, target='_blank')
                br()
        elif "actuator" in url:
            count += 1
            content = '[%s] ' % r.status_code + url + ' 疑似存在actuator信息泄漏，请自行确认'
            txt_report_file.write(content + '\n')
            with doc:
                a(content, href=url, target='_blank')
                br()
    else:
        pass


def req(url, path):  # 发送请求
    r = None
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/79.0.3945.88 Safari/537.36'}
        # if line1.startswith('https://'): #判断开头是否为https，若true则post
        #    full_url = line1.replace('\n','')+line2
        #    requests.packages.urllib3.disable_warnings()#关闭警告
        #    r = requests.post(full_url,headers=headers,allow_redirects=False,verify=False)证书校验关闭
        #    getRule(r,full_url,report)#调用判断方法
        # else:
        for app_name in open('dic/app_name.txt'):
            app_name = app_name.strip()
            full_url = url.replace('\n', '') + app_name.replace('\n', '')
            if full_url.endswith('/'):
                full_url = full_url[:-1]  # 去掉最后一个/
            full_url = full_url + path.replace('\n', '')
            print('开始检测的url:[%s]' % full_url)
            try:
                r = requests.get(full_url, headers=headers, allow_redirects=False)
            except:
                pass
            if r is not None:
                get_rule(r)
    except Exception as e:
        print(e)  # 输出异常信息
        sys.exit()


def get_url(path):
    try:
        # 通过for循环拼接拿到所有请求url
        for url in open('url.txt'):
            url = url.strip()  # 删除字符串首尾空格
            if url.endswith('/'):  # 判断传入的url是否携带/
                # 携带则去除
                req(url.strip('/'), path)  # 删除尾部/，strip只删除头尾部的关键字
            else:
                req(url, path)
    except:
        pass


if __name__ == '__main__':
    run()
    count = 0  # 疑似的漏洞数量
    txt_report = report_create('txt')  # 程序启动时，先创建报告文件
    txt_report_file = open(txt_report, 'a+')
    html_report = report_create('html')  # 程序启动时，先创建报告文件
    title = Path(html_report).stem
    doc = dominate.document(title=title)
    try:
        # 多线程异步抓取
        # 根据敏感路径
        threads = [threading.Thread(target=get_url, args=(line2,)) for line2 in
                   open('dic/path.txt')]  # 循环读取路径，并调用get_url函数
        for t in threads:
            t.start()  # 开启线程
        for t in threads:
            t.join()  # join所完成的工作就是线程同步，即主线程任务结束之后，进入阻塞状态，一直等待其他的子线程执行结束之后，主线程在终止
    except Exception as e:
        print(e)

    try:
        txt_report_file.close()
        with open(html_report, 'w') as f:
            f.write(doc.render())
        if count != 0:  # 检测是否存在漏洞
            print('测试结束，共发现%s处疑似存在该漏洞的URL' % count)
            print('测试结果已保存至result文件夹下的%s中' % txt_report)
        else:
            os.remove(txt_report)  # 不存在则删除报告文件
            print('测试结束，未发现疑似存在漏洞的URL')
    except Exception as e:
        print(e)
    # # 解决打包生成的exe运行完直接退出的问题
    # os.system('pause')
