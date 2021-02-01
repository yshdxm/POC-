

```
用户可以使用如下方法进行自查： 以非root用户登录系统，并使用命令sudoedit -s /
如果响应一个以sudoedit:开头的报错，那么表明存在漏洞。
如果响应一个以usage:开头的报错，那么表明补丁已经生效。
```

poc地址：

https://haxx.in/CVE-2021-3156_nss_poc_ubuntu.tar.gz

![](https://mmbiz.qpic.cn/mmbiz_png/ibNDXshVhQuuYhwhtibQdcEn3UNoOfjKcTQ2C5SzcibGbTWqNfCpeUavf5FOtXZjzRNdHKWcXPrlH7yhSoacxM3WQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

经过测试，该POC适用于ubuntu系列操作系统，已在ubuntu20.04与ubuntu 18.04上复现成功。



### 复现过程

进入到POC目录下，输入make，将在当前目录生成可执行文件：sudo-hax-me-a-sandwich，随后执行改文件即可，过程如下：

![](https://mmbiz.qpic.cn/mmbiz_png/ibNDXshVhQuuYhwhtibQdcEn3UNoOfjKcTUqnMncEo7jndePb2OZBRhVzicCXPYFaKw1DBAa0ffvoS4tb1qpIE92g/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)