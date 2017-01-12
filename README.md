# 醉考拉_tomcat弱口令扫描器 v1.0
简介：一款tomcat弱口令扫描器，支持ip、端口批量扫描

命令行版：koala_tomcat_cmd.py
使用方式：python koala_tomcat_cmd.py -h ip -p port -m 100 -t 10
-h 必输参数，支持ip(192.168.1.1)，ip段（192.168.1），ip范围指定（192.168.1.1-192.168.1.254）,ip列表文件（ip.ini）。
-p 指定要扫描端口列表，多个端口使用,隔开 例如：7001,8080,9999。未指定即使用port.txt内置端口进行扫描
-m 指定线程数量 默认100线程
-t 指定HTTP请求超时时间，默认为10秒，端口扫描超时为值的1/2。
默认漏洞结果保存在 result.log中

gui版：koala_tomcat_gui.py koala_tomcat_gui.exe
使用方式：中文图形界面使用方式就不多说啦，配置文件和命令行版的一样。
