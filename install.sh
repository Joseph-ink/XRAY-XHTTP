#!/bin/bash

# Nginx + Xray 自动化部署脚本
# 支持多域名SNI分流和自动TLS证书管理

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置变量
NGINX_DIR="/usr/local/nginx"
NGINX_CONF="/etc/nginx/nginx.conf"
NGINX_SERVICE="/etc/systemd/system/nginx.service"
XRAY_DIR="/usr/local/xray"
XRAY_CONF="/usr/local/etc/xray/config.json"
XRAY_SERVICE="/etc/systemd/system/xray.service"
CERT_DIR="/etc/ssl/xray"
ACME_SCRIPT="/root/.acme.sh/acme.sh"
SOCKET_PATH="/dev/shm/xray.socket"
COMPILE_PATH="/tmp/nginx_compile"
NGINX_INSTALL_METHOD="" # package 或 compile

# 打印信息函数
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本必须以root权限运行"
        exit 1
    fi
}

# 创建必要目录
create_directories() {
    print_info "创建必要目录..."
    mkdir -p /var/log/nginx
    mkdir -p /var/www/html
    mkdir -p /usr/local/etc/xray
    mkdir -p $CERT_DIR
    print_success "目录创建完成"
}

# 选择Nginx安装方式
select_nginx_install_method() {
    echo ""
    echo -e "${GREEN}请选择Nginx安装方式:${NC}"
    echo "1) 软件源安装 (快速，约1-2分钟)"
    echo "2) 源码编译安装 (高性能，约5-15分钟，根据CPU性能)"
    echo ""
    read -p "请选择 [1-2，默认1]: " nginx_method_choice

    case ${nginx_method_choice:-1} in
        1)
            NGINX_INSTALL_METHOD="package"
            print_info "已选择: 软件源安装"
            ;;
        2)
            NGINX_INSTALL_METHOD="compile"
            print_info "已选择: 源码编译安装（静态编译，优化性能）"
            ;;
        *)
            NGINX_INSTALL_METHOD="package"
            print_info "已选择: 软件源安装"
            ;;
    esac
}

# 检测CPU架构并生成编译优化参数
detect_cpu_optimization() {
    local arch=$(uname -m)
    local os=$(uname -s)
    local cc_opt=""

    # 基础优化参数（适用于所有架构）
    cc_opt="-g0 -O3 -fstack-reuse=all -fdwarf2-cfi-asm -fplt -fno-trapv -fno-exceptions"
    cc_opt="$cc_opt -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-check"
    cc_opt="$cc_opt -fno-stack-clash-protection -fno-stack-protector -fcf-protection=none"
    cc_opt="$cc_opt -fno-split-stack -fno-sanitize=all -fno-instrument-functions"

    # 根据架构添加特定优化
    case $arch in
        x86_64)
            # 检测是否支持更高级的指令集
            if grep -q "avx2" /proc/cpuinfo 2>/dev/null; then
                cc_opt="$cc_opt -march=x86-64-v3 -mtune=generic"
            elif grep -q "sse4" /proc/cpuinfo 2>/dev/null; then
                cc_opt="$cc_opt -march=x86-64-v2 -mtune=generic"
            else
                cc_opt="$cc_opt -march=x86-64 -mtune=generic"
            fi
            ;;
        aarch64|arm64)
            cc_opt="$cc_opt -march=armv8-a+crc+crypto -mtune=generic"
            ;;
        armv7l|armv7*)
            cc_opt="$cc_opt -march=armv7-a -mtune=generic-armv7-a -mfpu=neon"
            ;;
        *)
            # 未知架构使用通用优化
            ;;
    esac

    echo "$cc_opt"
}

# 更新软件源并安装依赖
install_dependencies() {
    print_info "更新软件源..."
    apt-get update -y

    print_info "安装依赖包..."

    # 基础依赖（所有安装方式都需要）
    local base_deps="curl wget sudo socat cron tar gzip unzip openssl ca-certificates"

    if [[ "$NGINX_INSTALL_METHOD" == "compile" ]]; then
        print_info "安装编译依赖..."

        # 检测并安装 PCRE 库（兼容新旧版本系统）
        local pcre_packages=""
        if apt-cache show libpcre3 &>/dev/null; then
            pcre_packages="libpcre3 libpcre3-dev"
            print_info "检测到 libpcre3 可用"
        fi
        if apt-cache show libpcre2-dev &>/dev/null; then
            pcre_packages="$pcre_packages libpcre2-dev"
            print_info "检测到 libpcre2 可用"
        fi

        # 如果都不可用，尝试只安装 libpcre2-dev
        if [[ -z "$pcre_packages" ]]; then
            print_warning "未检测到 PCRE 包，尝试安装 libpcre2-dev"
            pcre_packages="libpcre2-dev"
        fi

        # 编译安装需要的额外依赖
        apt-get install -y $base_deps \
            build-essential cmake git pkg-config \
            $pcre_packages \
            zlib1g-dev libssl-dev \
            libxml2-dev libxslt1-dev \
            libgd-dev libgeoip-dev \
            libperl-dev perl-base perl 2>/dev/null || {
                # 如果安装失败，尝试不安装可选依赖
                print_warning "部分可选依赖安装失败，尝试安装核心依赖..."
                apt-get install -y $base_deps \
                    build-essential cmake git pkg-config \
                    $pcre_packages \
                    zlib1g-dev libssl-dev
            }

        # 尝试安装 libgoogle-perftools-dev（可选，某些系统没有）
        apt-get install -y libgoogle-perftools-dev 2>/dev/null || print_warning "libgoogle-perftools-dev 不可用，跳过"
    else
        print_info "安装软件包依赖..."
        # 软件源安装只需要基础依赖
        apt-get install -y $base_deps libssl-dev
    fi

    print_success "依赖安装完成"
}

# 编译安装Nginx
compile_install_nginx() {
    print_info "开始编译安装Nginx..."

    # 清理旧的编译目录
    if [[ -d "$COMPILE_PATH" ]]; then
        print_info "清理旧的编译目录..."
        rm -rf $COMPILE_PATH
    fi

    # 创建编译目录
    mkdir -p $COMPILE_PATH
    cd $COMPILE_PATH

    # 使用最新的主线版本nginx
    local NGINX_VERSION="1.29.3"  # Nginx最新主线版
    print_info "使用Nginx版本: $NGINX_VERSION (主线版)"

    # 下载nginx源码
    print_info "下载Nginx源码..."
    wget -q https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
    tar -zxf nginx-$NGINX_VERSION.tar.gz
    rm nginx-$NGINX_VERSION.tar.gz
    mv nginx-$NGINX_VERSION nginx_src

    # 下载并编译ngx_brotli模块
    print_info "下载Brotli模块..."
    git clone --depth=1 https://github.com/google/ngx_brotli
    cd ngx_brotli
    git submodule update --init --recursive
    cd ..

    # 获取CPU优化参数
    print_info "配置编译优化参数..."
    local arch=$(uname -m)
    print_info "检测到系统架构: $arch"

    local CC_OPT=$(detect_cpu_optimization)

    # 显示优化信息
    if echo "$CC_OPT" | grep -q "x86-64-v3"; then
        print_info "应用 x86-64-v3 优化 (AVX2)"
    elif echo "$CC_OPT" | grep -q "x86-64-v2"; then
        print_info "应用 x86-64-v2 优化 (SSE4)"
    elif echo "$CC_OPT" | grep -q "armv8"; then
        print_info "应用 ARM64 优化"
    elif echo "$CC_OPT" | grep -q "armv7"; then
        print_info "应用 ARMv7 优化"
    else
        print_info "应用通用优化"
    fi

    # 创建nginx用户
    if ! id -u nginx &>/dev/null; then
        print_info "创建nginx用户..."
        useradd -M -s /sbin/nologin nginx
    fi

    # 创建必要的目录
    mkdir -p /var/cache/nginx
    mkdir -p /etc/nginx/conf.d

    # 进入源码目录并配置
    cd nginx_src
    print_info "配置Nginx编译选项..."

    # 检测PCRE版本
    if pkg-config --exists libpcre2-8 2>/dev/null; then
        print_info "检测到 PCRE2 库"
    elif pkg-config --exists libpcre 2>/dev/null; then
        print_info "检测到 PCRE 库"
    fi

    ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/var/run/nginx.pid \
        --lock-path=/var/run/nginx.lock \
        --http-client-body-temp-path=/var/cache/nginx/client_temp \
        --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
        --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
        --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
        --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
        --user=nginx \
        --group=nginx \
        --with-threads \
        --with-file-aio \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_realip_module \
        --with-http_addition_module \
        --with-http_xslt_module=dynamic \
        --with-http_image_filter_module=dynamic \
        --with-http_geoip_module=dynamic \
        --with-http_sub_module \
        --with-http_dav_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_auth_request_module \
        --with-http_random_index_module \
        --with-http_secure_link_module \
        --with-http_degradation_module \
        --with-http_slice_module \
        --with-http_stub_status_module \
        --with-http_perl_module=dynamic \
        --with-mail=dynamic \
        --with-mail_ssl_module \
        --with-stream=dynamic \
        --with-stream_ssl_module \
        --with-stream_realip_module \
        --with-stream_geoip_module=dynamic \
        --with-stream_ssl_preread_module \
        --add-module=$COMPILE_PATH/ngx_brotli \
        --with-compat \
        --with-cc-opt="$CC_OPT"

    if [[ $? -ne 0 ]]; then
        print_error "Nginx配置失败"
        exit 1
    fi

    # 编译
    print_info "开始编译Nginx（这可能需要几分钟）..."
    local cpu_cores=$(nproc)
    print_info "使用 $cpu_cores 个CPU核心进行编译"

    make -j$cpu_cores

    if [[ $? -ne 0 ]]; then
        print_error "Nginx编译失败"
        exit 1
    fi

    # 安装
    print_info "安装Nginx..."
    make install

    if [[ $? -ne 0 ]]; then
        print_error "Nginx安装失败"
        exit 1
    fi

    # 清理编译文件
    print_info "清理编译文件..."
    cd /
    rm -rf $COMPILE_PATH

    # 验证安装
    if nginx -v &>/dev/null; then
        local installed_version=$(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9.]+')
        print_success "Nginx编译安装完成! 版本: $installed_version"
        print_success "安装类型: 静态编译，高性能优化"
    else
        print_error "Nginx安装验证失败"
        exit 1
    fi
}

# 安装Nginx
install_nginx() {
    if command -v nginx &> /dev/null; then
        print_warning "Nginx已安装，跳过..."
        return
    fi

    if [[ "$NGINX_INSTALL_METHOD" == "compile" ]]; then
        compile_install_nginx
    else
        print_info "从软件源安装Nginx..."
        apt-get install -y nginx
        print_success "Nginx安装完成"
    fi

    # 停止nginx以便后续配置
    systemctl stop nginx 2>/dev/null || true
}

# 配置Nginx systemd服务
configure_nginx_service() {
    print_info "配置Nginx systemd服务..."

    if [[ "$NGINX_INSTALL_METHOD" == "compile" ]]; then
        # 编译安装需要创建systemd服务文件
        print_info "创建Nginx systemd服务文件..."
        cat > $NGINX_SERVICE << 'EOF'
[Unit]
Description=The NGINX HTTP and reverse proxy server
Documentation=https://nginx.org/en/docs/
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
        print_success "Nginx systemd服务文件创建完成"
    fi

    # 重载systemd并启用服务
    systemctl daemon-reload
    systemctl enable nginx.service
    print_success "Nginx服务配置完成"
}

# 创建默认网页
create_default_page() {
    print_info "创建默认网页..."
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>Welcome to Nginx</h1>
    <p>Server is running successfully.</p>
</body>
</html>
EOF
    print_success "默认网页创建完成"
}

# 检查acme.sh是否已安装
check_acme() {
    if [[ -f "$ACME_SCRIPT" ]]; then
        print_info "acme.sh已安装"
        return 0
    else
        return 1
    fi
}

# 安装acme.sh
install_acme() {
    if check_acme; then
        print_warning "acme.sh已存在，跳过安装"
        return
    fi
    
    print_info "安装acme.sh..."
    curl -s https://get.acme.sh | sh
    ln -sf /root/.acme.sh/acme.sh /usr/local/bin/acme.sh
    
    print_success "acme.sh安装完成"
}

# 选择CA机构
select_ca() {
    echo ""
    echo -e "${GREEN}请选择证书颁发机构 (CA):${NC}"
    echo "1) Let's Encrypt (推荐，完全免费，最稳定)"
    echo "2) ZeroSSL (免费，需要邮箱注册)"
    echo "3) Google Trust Services (Google提供，免费)"
    echo "4) SSL.com (免费90天证书)"
    echo ""
    read -p "请选择 [1-4，默认1]: " ca_choice
    
    case ${ca_choice:-1} in
        1)
            CA_SERVER="letsencrypt"
            CA_NAME="Let's Encrypt"
            ;;
        2)
            CA_SERVER="zerossl"
            CA_NAME="ZeroSSL"
            # ZeroSSL需要邮箱
            echo ""
            print_warning "ZeroSSL 需要注册账号"
            read -p "请输入邮箱地址: " ca_email
            if [[ -n "$ca_email" ]]; then
                $ACME_SCRIPT --register-account -m "$ca_email" --server zerossl
            else
                print_error "必须提供邮箱地址"
                CA_SERVER="letsencrypt"
                CA_NAME="Let's Encrypt (已切换)"
                print_warning "已自动切换到 Let's Encrypt"
            fi
            ;;
        3)
            CA_SERVER="google"
            CA_NAME="Google Trust Services"
            ;;
        4)
            CA_SERVER="ssl.com"
            CA_NAME="SSL.com"
            ;;
        *)
            CA_SERVER="letsencrypt"
            CA_NAME="Let's Encrypt"
            ;;
    esac
    
    print_info "设置CA为: $CA_NAME"
    $ACME_SCRIPT --set-default-ca --server $CA_SERVER
    
    # 保存CA选择
    echo "$CA_SERVER" > /tmp/xray_ca.txt
    
    print_success "CA设置完成"
}

# 申请TLS证书
apply_certificate() {
    local domain=$1
    local cert_path="$CERT_DIR/${domain}"
    
    mkdir -p "$cert_path"
    
    # 检查证书是否已存在且有效
    if [[ -f "$cert_path/fullchain.cer" ]] && [[ -f "$cert_path/private.key" ]]; then
        local expiry_date=$(openssl x509 -enddate -noout -in "$cert_path/fullchain.cer" | cut -d= -f2)
        local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_date" +%s 2>/dev/null)
        local current_epoch=$(date +%s)
        local days_left=$(( ($expiry_epoch - $current_epoch) / 86400 ))
        
        if [[ $days_left -gt 30 ]]; then
            print_warning "域名 $domain 的证书仍有效（剩余${days_left}天），跳过申请"
            return 0
        fi
    fi
    
    print_info "为域名 $domain 申请证书..."
    
    # 临时停止nginx以通过HTTP验证
    local nginx_was_running=false
    if systemctl is-active --quiet nginx; then
        nginx_was_running=true
        systemctl stop nginx
    fi
    
    # 申请证书 - 使用standalone模式进行HTTP-01验证
    print_info "使用 HTTP-01 验证方式申请证书..."
    $ACME_SCRIPT --issue -d "$domain" --standalone --httpport 80 --force
    
    if [[ $? -ne 0 ]]; then
        print_error "证书申请失败"
        if [[ $nginx_was_running == true ]]; then
            systemctl start nginx
        fi
        return 1
    fi
    
    # 安装证书（不设置reload命令，避免nginx未运行时报错）
    $ACME_SCRIPT --install-cert -d "$domain" \
        --key-file "$cert_path/private.key" \
        --fullchain-file "$cert_path/fullchain.cer"
    
    # 恢复nginx状态
    if [[ $nginx_was_running == true ]]; then
        systemctl start nginx
    fi
    
    print_success "域名 $domain 证书申请完成"
}

# 生成随机路径
generate_random_path() {
    echo "/$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
}

# 配置Nginx
configure_nginx() {
    local domains=("$@")
    
    print_info "配置Nginx..."
    
    # 生成随机路径
    local random_path=$(generate_random_path)
    echo "$random_path" > /tmp/xray_path.txt
    
    # 查找mime.types文件位置
    local mime_types_path=""
    for path in "/etc/nginx/mime.types" "/usr/share/nginx/mime.types" "/usr/local/nginx/conf/mime.types"; do
        if [[ -f "$path" ]]; then
            mime_types_path="$path"
            break
        fi
    done
    
    # 如果找不到mime.types，创建一个基本的
    if [[ -z "$mime_types_path" ]]; then
        mime_types_path="/etc/nginx/mime.types"
        cat > "$mime_types_path" << 'MIME_EOF'
types {
    text/html                             html htm shtml;
    text/css                              css;
    text/xml                              xml;
    image/gif                             gif;
    image/jpeg                            jpeg jpg;
    application/javascript                js;
    application/atom+xml                  atom;
    application/rss+xml                   rss;
    text/plain                            txt;
    image/png                             png;
    image/x-icon                          ico;
    image/svg+xml                         svg svgz;
    application/json                      json;
}
MIME_EOF
    fi
    
    # 开始写入nginx配置 - 使用临时文件避免变量展开问题
    cat > $NGINX_CONF << 'NGINX_CONF_START'
user www-data;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
NGINX_CONF_START

    # 添加mime.types路径
    echo "    include $mime_types_path;" >> $NGINX_CONF
    
    # 继续写入配置
    cat >> $NGINX_CONF << 'NGINX_CONF_MIDDLE'
    default_type application/octet-stream;
    
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    client_max_body_size 0;
    
    gzip on;
    
    # SSL通用配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
NGINX_CONF_MIDDLE

    # 为每个域名添加server块
    for domain in "${domains[@]}"; do
        cat >> $NGINX_CONF << DOMAIN_BLOCK
    server {
        listen 443 ssl;
        listen [::]:443 ssl;
        http2 on;
        server_name $domain;
        
        root /var/www/html;
        index index.html;
        
        ssl_certificate $CERT_DIR/${domain}/fullchain.cer;
        ssl_certificate_key $CERT_DIR/${domain}/private.key;
        
        client_header_timeout 5m;
        keepalive_timeout 5m;
        
        location $random_path {
            client_max_body_size 0;
            grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            client_body_timeout 5m;
            grpc_read_timeout 315;
            grpc_send_timeout 5m;
            grpc_pass unix:${SOCKET_PATH};
        }
        
        location / {
            try_files \$uri \$uri/ =404;
        }
    }
    
DOMAIN_BLOCK
    done
    
    # 添加HTTP到HTTPS重定向并关闭http块
    cat >> $NGINX_CONF << 'NGINX_CONF_END'
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        return 301 https://$host$request_uri;
    }
}
NGINX_CONF_END
    
    print_success "Nginx配置完成"
}

# 验证并重启Nginx
restart_nginx() {
    print_info "验证Nginx配置..."
    if nginx -t; then
        print_success "Nginx配置验证通过"
        systemctl restart nginx
        print_success "Nginx已重启"
    else
        print_error "Nginx配置验证失败"
        exit 1
    fi
}

# 获取系统架构
get_architecture() {
    local arch=$(uname -m)
    case $arch in
        x86_64)
            echo "linux-64"
            ;;
        aarch64)
            echo "linux-arm64-v8a"
            ;;
        armv7l)
            echo "linux-arm32-v7a"
            ;;
        *)
            print_error "不支持的架构: $arch"
            exit 1
            ;;
    esac
}

# 安装Xray
install_xray() {
    print_info "检测系统架构..."
    local arch=$(get_architecture)
    print_info "系统架构: $arch"
    
    print_info "获取Xray最新版本..."
    local latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
    print_info "最新版本: $latest_version"
    
    local download_url="https://github.com/XTLS/Xray-core/releases/download/${latest_version}/Xray-${arch}.zip"
    
    print_info "下载Xray..."
    cd /tmp
    wget -q "$download_url" -O xray.zip
    
    print_info "解压Xray..."
    unzip -q -o xray.zip -d xray-tmp
    
    mkdir -p $XRAY_DIR
    mv xray-tmp/xray $XRAY_DIR/
    chmod +x $XRAY_DIR/xray
    
    rm -rf xray-tmp xray.zip
    
    print_success "Xray安装完成"
}

# 配置Xray systemd服务
configure_xray_service() {
    print_info "配置Xray systemd服务..."
    
    cat > $XRAY_SERVICE << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_DIR/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable xray.service
    print_success "Xray服务配置完成"
}

# 生成UUID
generate_uuid() {
    if command -v $XRAY_DIR/xray &> /dev/null; then
        $XRAY_DIR/xray uuid
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# 配置Xray
configure_xray() {
    local path=$1
    
    print_info "生成UUID..."
    local uuid=$(generate_uuid)
    
    print_info "配置Xray..."
    cat > $XRAY_CONF << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "inbounds": [
        {
            "listen": "${SOCKET_PATH}",
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "level": 0
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {
                    "path": "${path}",
                    "host": ""
                },
                "sockopt": {
                    "acceptProxyProtocol": false
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ]
}
EOF
    
    # 创建日志目录
    mkdir -p /var/log/xray
    
    echo "$uuid" > /tmp/xray_uuid.txt
    
    print_success "Xray配置完成"
}

# 修复 Socket 权限
fix_socket_permissions() {
    print_info "配置 Socket 权限..."
    
    # 创建 systemd drop-in 目录
    mkdir -p /etc/systemd/system/xray.service.d
    
    # 创建权限修复配置
    cat > /etc/systemd/system/xray.service.d/socket-permissions.conf << 'EOF'
[Service]
ExecStartPost=/bin/bash -c 'while [ ! -S /dev/shm/xray.socket ]; do sleep 0.1; done; chmod 666 /dev/shm/xray.socket'
EOF
    
    systemctl daemon-reload
    
    print_success "Socket 权限配置完成"
}

# 验证并重启Xray
restart_xray() {
    print_info "验证Xray配置..."
    if $XRAY_DIR/xray -test -config $XRAY_CONF; then
        print_success "Xray配置验证通过"
        systemctl restart xray
        sleep 2
        if systemctl is-active --quiet xray; then
            print_success "Xray已启动"
        else
            print_error "Xray启动失败"
            journalctl -u xray -n 20
            exit 1
        fi
    else
        print_error "Xray配置验证失败"
        exit 1
    fi
}

# 完整安装流程
full_install() {
    clear
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}  Nginx + Xray 自动化部署${NC}"
    echo -e "${GREEN}================================${NC}"
    echo ""

    check_root
    create_directories

    # 选择Nginx安装方式
    select_nginx_install_method

    install_dependencies
    install_nginx
    configure_nginx_service
    create_default_page
    install_acme
    
    # 选择CA机构
    select_ca
    
    # 询问域名
    echo ""
    print_info "请输入要配置的域名（多个域名用空格分隔）："
    read -p "> " domains_input
    IFS=' ' read -ra domains <<< "$domains_input"
    
    if [[ ${#domains[@]} -eq 0 ]]; then
        print_error "未输入域名"
        exit 1
    fi
    
    # 申请证书
    for domain in "${domains[@]}"; do
        apply_certificate "$domain"
    done
    
    # 配置Nginx
    configure_nginx "${domains[@]}"
    restart_nginx
    
    # 安装Xray
    install_xray
    configure_xray_service
    
    # 获取路径并配置Xray
    local path=$(cat /tmp/xray_path.txt)
    configure_xray "$path"
    fix_socket_permissions
    restart_xray
    
    echo ""
    print_success "========================================="
    print_success "安装完成！"
    print_success "========================================="
    
    show_proxy_info
}

# 显示代理信息
show_proxy_info() {
    if [[ ! -f /tmp/xray_uuid.txt ]] || [[ ! -f /tmp/xray_path.txt ]]; then
        print_error "未找到配置信息，请先完成安装"
        return
    fi
    
    local uuid=$(cat /tmp/xray_uuid.txt)
    local path=$(cat /tmp/xray_path.txt)
    local domains_input
    
    if [[ -f $NGINX_CONF ]]; then
        domains_input=$(grep -oP 'server_name \K[^;]+' $NGINX_CONF | grep -v '_' | head -n 1)
    else
        read -p "请输入域名: " domains_input
    fi
    
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}代理配置信息${NC}"
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${BLUE}协议:${NC} VLESS"
    echo -e "${BLUE}UUID:${NC} ${uuid}"
    echo -e "${BLUE}域名:${NC} ${domains_input}"
    echo -e "${BLUE}端口:${NC} 443"
    echo -e "${BLUE}传输:${NC} XHTTP"
    echo -e "${BLUE}路径:${NC} ${path}"
    echo -e "${BLUE}TLS:${NC} 启用"
    
    # 显示CA信息
    if [[ -f /tmp/xray_ca.txt ]]; then
        local ca_server=$(cat /tmp/xray_ca.txt)
        local ca_display=""
        case $ca_server in
            letsencrypt) ca_display="Let's Encrypt" ;;
            zerossl) ca_display="ZeroSSL" ;;
            google) ca_display="Google Trust Services" ;;
            ssl.com) ca_display="SSL.com" ;;
            *) ca_display="$ca_server" ;;
        esac
        echo -e "${BLUE}证书CA:${NC} $ca_display"
    fi
    
    echo -e "${GREEN}=========================================${NC}"
    echo ""
}

# 部分卸载（保留acme.sh）
partial_uninstall() {
    print_warning "开始部分卸载（保留acme.sh）..."

    systemctl stop xray nginx 2>/dev/null || true
    systemctl disable xray nginx 2>/dev/null || true

    rm -rf $XRAY_DIR
    rm -f $XRAY_SERVICE
    rm -rf /usr/local/nginx
    rm -rf /etc/nginx
    rm -rf /var/log/nginx
    rm -rf /var/www/html
    rm -rf /var/cache/nginx
    rm -f /tmp/xray_*.txt

    # 删除nginx可执行文件（编译安装）
    rm -f /usr/sbin/nginx
    rm -f $NGINX_SERVICE
    rm -rf /usr/lib/nginx

    # 卸载nginx软件包（软件源安装）
    apt-get remove -y nginx nginx-common 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true

    systemctl daemon-reload

    print_success "部分卸载完成（已保留acme.sh和证书）"
}

# 完全卸载
full_uninstall() {
    print_warning "开始完全卸载..."
    
    partial_uninstall
    
    rm -rf /root/.acme.sh
    rm -f /usr/local/bin/acme.sh
    rm -rf $CERT_DIR
    
    print_success "完全卸载完成"
}

# 重启服务
restart_services() {
    echo ""
    echo "1) 重启Nginx"
    echo "2) 重启Xray"
    echo "3) 重启所有服务"
    echo "0) 返回"
    echo ""
    read -p "请选择: " choice
    
    case $choice in
        1)
            systemctl restart nginx
            print_success "Nginx已重启"
            ;;
        2)
            systemctl restart xray
            print_success "Xray已重启"
            ;;
        3)
            systemctl restart nginx xray
            print_success "所有服务已重启"
            ;;
        0)
            return
            ;;
        *)
            print_error "无效选择"
            ;;
    esac
}

# 主菜单
main_menu() {
    while true; do
        clear
        echo -e "${GREEN}================================${NC}"
        echo -e "${GREEN}  Nginx + Xray 管理脚本${NC}"
        echo -e "${GREEN}================================${NC}"
        echo ""
        echo "1) 完整安装"
        echo "2) 卸载"
        echo "3) 重启服务"
        echo "4) 显示代理信息"
        echo "0) 退出"
        echo ""
        read -p "请选择操作: " choice
        
        case $choice in
            1)
                full_install
                read -p "按回车键继续..."
                ;;
            2)
                echo ""
                echo "1) 部分卸载（保留acme.sh）"
                echo "2) 完全卸载"
                echo "0) 返回"
                echo ""
                read -p "请选择: " uninstall_choice
                case $uninstall_choice in
                    1)
                        partial_uninstall
                        read -p "按回车键继续..."
                        ;;
                    2)
                        full_uninstall
                        read -p "按回车键继续..."
                        ;;
                    0)
                        continue
                        ;;
                    *)
                        print_error "无效选择"
                        read -p "按回车键继续..."
                        ;;
                esac
                ;;
            3)
                restart_services
                read -p "按回车键继续..."
                ;;
            4)
                show_proxy_info
                read -p "按回车键继续..."
                ;;
            0)
                print_info "退出脚本"
                exit 0
                ;;
            *)
                print_error "无效选择"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 启动脚本
main_menu