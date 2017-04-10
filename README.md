# 醉考拉_tomcat弱口令扫描器 v1.0

本软件仅供对客户已授权的系统使用！

简介：一款tomcat后台弱口令扫描器。支持多线程、多ip、多端口批量扫描，支持自定义弱口令字典。

### 图形界面版：koala_tomcat_gui.exe  koala_tomcat_gui.py 

介绍：界面使用pyqt4开发，koala_tomcat_gui.exe支持windows平台，koala_tomcat_gui.py需要pyqt4库支持。使用pyinstaller转py为exe，部分二逼杀软会误报，不放心的请执行py。

使用方式：看图。

![](https://github.com/magicming200/tomcat-weak-password-scanner/blob/master/koala_tomcat_gui_screenshot.png)

### 命令行版：koala_tomcat_cmd.py

使用方式：python koala_tomcat_cmd.py -h ip -p port -m 100 -t 10

-h 必须输入参数，支持ip(192.168.1.1)，ip段（192.168.1），ip范围指定（192.168.1.1-192.168.5.100）,ip列表文件（ip.txt）。

-p 可选参数，指定要扫描端口列表，多个端口使用英文逗号,隔开，未指定即使用port.txt内置端口进行扫描

-m 可选参数，指定线程数量，默认100

-t 可选参数，指定HTTP请求超时时间，默认为10秒，端口扫描超时为值的1/2。

默认漏洞结果保存在 result.txt中


