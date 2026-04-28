## XRAY XHTTP TLS 一键安装脚本

### 仅支持Nginx 前置 Vless xhttp tls协议

**需要自备域名并解析**


| 特点 |
| :--- |
| 1、Nginx支持软件源安装（快速）和编译安装（高性能） |
| 2、支持自动申请多域名、多IP TLS证书 |
| 3、Nginx前置分流至后端Xray Core|
| 4、充分利用Xray XHTTP特性，enjoy! |


### 快速安装
```
wget -N --no-check-certificate "https://raw.githubusercontent.com/Joseph-ink/XRAY-XHTTP/refs/heads/main/install.sh" && chmod +x install.sh && ./install.sh
```


| 项目 | **Joseph-ink/XRAY-XHTTP** |
| :--- | :--- |
| Nginx程序 | **/etc/nginx/nginx** |
| Nginx配置 | **/etc/nginx/nginx.conf** |
| Xray程序 | **/etc/xray/xray** |
| Xray配置 | **/etc/xray/config.json** |
| TLS证书 | **/root/cert/** |  



### 免责声明
本项目脚本使用Vibe Coding 自动编写，目的主要在于自用。
请审核确认代码安全，若存在Bug请PR修复，使用时请遵守当地法律。
