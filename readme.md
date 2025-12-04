## XRAY XHTTP TLS 一键安装脚本

### 仅支持Vless xhttp tls协议

**需要自备域名并解析**


| 特点 |
| :--- |
| 1、Nginx支持软件源安装（快速）和编译安装（高性能） |
| 2、支持自动申请多域名TLS证书 |
| 3、Nginx前置SNI分流至后端Xray |
| 4、充分利用Xray XHTTP特性，enjoy! |


### 快速安装
```
wget -N --no-check-certificate "https://raw.githubusercontent.com/Joseph-ink/XRAY-XHTTP/main/install.sh" && chmod +x install.sh && ./install.sh  
```


| 项目 | **Joseph-ink/XRAY-XHTTP** |
| :--- | :--- |
| Nginx程序 | **/usr/sbin/nginx** |
| Nginx配置 | **/etc/nginx/nginx.conf** |
| Xray程序 | **/usr/local/xray/xray** |
| Xray配置 | **/usr/local/etc/xray/config.json** |
| TLS证书 | **/etc/ssl/xray/** |  

### 免责生命
本项目脚本使用Claude Code自动编写，目的主要在于自用，请遵守当地法律。
使用一键脚本前请审核代码确认安全，若存在Bug请PR修复。
