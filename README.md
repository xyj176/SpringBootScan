# SpringBootScan
    扫描网站是否存在SpringBoot API信息泄漏或阿里云存储OSSKEY泄漏
    Scan the website for Spring Boot API information leakage or Alibaba Cloud storage OSSKEY leakage

<h2>For Example:</h2>
<code>python3 SpringBootScan.py</code>
<p></p>
<p></p>

    * 将需要测试的域名放入url.txt中，格式如下：
      https://www.example.com
      https://ip:port

    * 将应用的名称放入【dic】下的app_name.txt,格式如下：
      /
      /dgp

    * 将后续路径放入【dic】下的path.txt，格式如下：
      /nacos
      /app/kibana

    * 测试报告在result/目录下，报告命名为：时分秒
    * 边学边写，所以所有的注释就不删除了
