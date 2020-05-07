#!/bin/bash
nginx_version=nginx-1.18.0
openssl_version=openssl-3.0.0-alpha1

#定义几个颜色
tyblue()                           #天依蓝
{
    echo -e "\033[36;1m ${1}\033[0m"
}
green()                            #水鸭青
{
    echo -e "\033[32;1m ${1}\033[0m"
}
yellow()                           #鸭屎黄
{
    echo -e "\033[33;1m ${1}\033[0m"
}
red()                              #姨妈红
{
    echo -e "\033[31;1m ${1}\033[0m"
}


if [ "$EUID" != "0" ]; then
    red "请用root用户运行此脚本！！"
    exit 1
fi


if [ -f /etc/redhat-release ]; then
    release="centos"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
elif command -v apt > /dev/null 2>&1 && ! command -v yum > /dev/null 2>&1; then
    release="debian"
elif command -v yum > /dev/null 2>&1 && ! command -v apt > /dev/null 2>&1; then
    release="centos"
else
    red "不支持的系统！！"
    exit 1
fi

if [ -e /etc/v2ray/config.json ] && [ -e /etc/nginx ] ; then
    is_installed=1
else
    is_installed=0
fi

systemVersion=`lsb_release -r --short`

#版本比较函数
version_ge()
{
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

#读取域名
readDomain()
{
    check_domain()
    {
        local temp=${1%%.*}
        if [ "$temp" == "www" ]; then
            red "域名前面不要带www！"
            return 0
        elif [ "$1" == "" ]; then
            return 0
        else
            return 1
        fi
    }
    echo -e "\n\n\n"
    tyblue "**********************关于域名的说明**********************"
    tyblue "假设你的域名是abcd.com，则:"
    tyblue "一级域名为:abcd.com(主机记录为 @ )"
    tyblue "二级域名为:xxx.abcd.com(如www.abcd.com，pan.abcd.com，前缀为主机记录)"
    tyblue "三级域名为:xxx.xxx.abcd.com"
    tyblue "可以在cmd里用ping+域名来查看域名的解析情况"
    tyblue "**********************************************************"
    echo
    tyblue "**********************************************************"
    tyblue "若你有多个域名，但想只用某个解析到此服务器的域名，请选择2并输入该域名"
    tyblue "注:在这里拥有相同一级域名的二(三)级域名也算不同域名"
    tyblue "如:www.abcd.com，pan.abcd.com，abcd.com，abcd2.com算不同域名"
    echo
    tyblue "********************请选择域名解析情况********************"
    tyblue "1.一级域名和  www.一级域名  都解析到此服务器上"
    tyblue "2.仅一级域名或某个二(三)级域名解析到此服务器上"
    domainconfig=""
    while [ "$domainconfig" != "1" -a "$domainconfig" != "2" ]
    do
        read -p "您的选择是：" domainconfig
    done
    case "$domainconfig" in
        1)
            echo
            tyblue "********************请输入一级域名(不带www.，http，:，/)********************"
            read -p "请输入域名：" domain
            while check_domain $domain ;
            do
                read -p "请输入域名：" domain
            done
            ;;
        2)
            echo
            tyblue "****************请输入解析到此服务器的域名(不带http，:，/)****************"
            read -p "请输入域名：" domain
            ;;
    esac
    echo -e "\n\n\n"
    tyblue "******************************请选择要伪装的网站页面******************************"
    tyblue "1.404页面 (模拟网站后台)"
    green  "说明：大型网站几乎都有使用网站后台，比如bilibili的每个视频都是由"
    green  "另外一个域名提供的，直接访问那个域名的根目录将返回404或其他错误页面"
    tyblue "2.镜像腾讯视频网站"
    green  "说明：是真镜像站，非链接跳转，默认为腾讯视频，搭建完成后可以自己修改，可能构成侵权"
    tyblue "3.nextcloud登陆页面"
    green  "说明：nextclound是开源的私人网盘服务，假装你搭建了一个私人网盘(可以换成别的自定义网站)"
    echo
    pretend=""
    while [[ x"$pretend" != x"1" && x"$pretend" != x"2" && x"$pretend" != x"3" ]]
    do
        read -p "您的选择是：" pretend
    done
}


#选择tls配置
readTlsConfig()
{
    echo -e "\n\n\n"
    tyblue "****************************************************************"
    tyblue "                     速度                        抗封锁性"
    tyblue "TLS1.2+1.3：  ++++++++++++++++++++          ++++++++++++++++++++"
    tyblue "仅TLS1.3：    ++++++++++++++++++++          ++++++++++++++++++"
    tyblue "****************************************************************"
    tyblue "经测试，当TLS1.2和TLS1.3并存的时候，v2ray会优先选择TLS1.3进行连接"
    green  "推荐使用TLS1.2+1.3"
    echo
    tyblue "1.TLS1.2+1.3"
    tyblue "2.仅TLS1.3"
    tlsVersion=777
    while [ "$tlsVersion" != "1" -a "$tlsVersion" != "2" ]
    do
        read -p "您的选择是："  tlsVersion
    done
}


#配置nginx
configtls_init()
{
cat > /etc/nginx/conf/nginx.conf <<EOF

user  root root;
worker_processes  8;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;
google_perftools_profiles /etc/nginx/tcmalloc_temp/tcmalloc;

events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
    #                  '\$status \$body_bytes_sent "\$http_referer" '
    #                  '"\$http_user_agent" "\$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  1200s;

    #gzip  on;

    include       /etc/nginx/conf.d/v2ray.conf;
    #server {
        #listen       80;
        #server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        #location / {
        #    root   html;
        #    index  index.html index.htm;
        #}

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        #error_page   500 502 503 504  /50x.html;
        #location = /50x.html {
        #    root   html;
        #}

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \\.php\$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \\.php\$ {
        #    root           html;
        #    fastcgi_pass   127.0.0.1:9000;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME  /scripts\$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\\.ht {
        #    deny  all;
        #}
    #}


    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    #server {
    #    listen       8000;
    #    listen       somename:8080;
    #    server_name  somename  alias  another.alias;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}


    # HTTPS server
    #
    #server {
    #    listen       443 ssl;
    #    server_name  localhost;

    #    ssl_certificate      cert.pem;
    #    ssl_certificate_key  cert.key;

    #    ssl_session_cache    shared:SSL:1m;
    #    ssl_session_timeout  5m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5;
    #    ssl_prefer_server_ciphers  on;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}

}
EOF
}


#配置nginx 参数：  domain  tlsversion  domainconfig   path   port   pretend
configtls()
{
    configtls_init
cat > /etc/nginx/conf.d/v2ray.conf<<EOF
server {
    listen 80 fastopen=100 reuseport default_server;
    listen [::]:80 fastopen=100 reuseport default_server;
EOF
    if [ $3 -eq 1 ]; then
        echo "    return 301 https://www.$1;" >> /etc/nginx/conf.d/v2ray.conf
    else
        echo "    return 301 https://$1;" >> /etc/nginx/conf.d/v2ray.conf
    fi
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
}
server {
    listen 80;
    listen [::]:80;
    server_name $1;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2 fastopen=100 reuseport default_server;
    listen [::]:443 ssl http2 fastopen=100 reuseport default_server;
    ssl_certificate       /root/.acme.sh/${1}_ecc/fullchain.cer;
    ssl_certificate_key   /root/.acme.sh/${1}_ecc/$1.key;
EOF
    if [ $2 -eq 1 ]; then
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
    ssl_protocols         TLSv1.3 TLSv1.2;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
EOF
    else
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
    ssl_protocols         TLSv1.3;
EOF
    fi
    if [ $3 -eq 1 ]; then
        echo "    return 301 https://www.$1;" >> /etc/nginx/conf.d/v2ray.conf
    else
        echo "    return 301 https://$1;" >> /etc/nginx/conf.d/v2ray.conf
    fi
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $1;
    ssl_certificate       /root/.acme.sh/${1}_ecc/fullchain.cer;
    ssl_certificate_key   /root/.acme.sh/${1}_ecc/$1.key;
EOF
    if [ $2 -eq 1 ]; then
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
    ssl_protocols         TLSv1.3 TLSv1.2;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
EOF
    else
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
    ssl_protocols         TLSv1.3;
EOF
    fi
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /root/.acme.sh/${1}_ecc/fullchain.cer;
    add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload" always;
    root /etc/nginx/html/$1;
    location $4 {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$5;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
EOF
    if [ $6 -eq 2 ]; then
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
    location / {
        proxy_pass https://v.qq.com;
        proxy_set_header referer "https://v.qq.com";
    }
EOF
    fi
    echo '}' >> /etc/nginx/conf.d/v2ray.conf
    if [ $3 -eq 1 ]; then
        sed -i "s/server_name $1/& www.$1/" /etc/nginx/conf.d/v2ray.conf
    fi
}


#添加新域名
new_domain()
{
    readDomain
    get_certs $domain $domainconfig
    get_base_information
    configtls_init
    old_domain=$(grep -m 1 "server_name" /etc/nginx/conf.d/v2ray.conf)
    old_domain=${old_domain%';'*}
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $domain;
    ssl_certificate       /etc/nginx/certs/$domain.cer;
    ssl_certificate_key   /etc/nginx/certs/$domain.key;
EOF
    if [ $tlsVersion -eq 1 ]; then
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
    ssl_protocols         TLSv1.3 TLSv1.2;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
EOF
    else
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
    ssl_protocols         TLSv1.3;
EOF
    fi
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/nginx/certs/$domain.cer;
    add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload" always;
    root /etc/nginx/html/$domain;
    location $path {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
EOF
    if [ $pretend -eq 2 ]; then
cat >> /etc/nginx/conf.d/v2ray.conf<<EOF
    location / {
        proxy_pass https://v.qq.com;
        proxy_set_header referer "https://v.qq.com";
    }
EOF
    fi
    echo '}' >> /etc/nginx/conf.d/v2ray.conf
    if [ $domainconfig -eq 1 ]; then
        sed -i "0,/$old_domain/s//$old_domain $domain www.$domain/" /etc/nginx/conf.d/v2ray.conf
        sed -i "s/server_name $domain/& www.$domain/" /etc/nginx/conf.d/v2ray.conf
    else
        sed -i "0,/$old_domain/s//$old_domain $domain/" /etc/nginx/conf.d/v2ray.conf
    fi
}


#升级系统
updateSystem()
{
    echo -e "\n\n\n"
    tyblue "********************请选择升级系统版本********************"
    tyblue "1.最新beta版(现在是20.04)(2020.04)"
    tyblue "2.最新稳定版(现在是20.04)(2020.04)"
    tyblue "3.最新LTS版(现在是20.04)(2020.04)"
    tyblue "*************************版本说明*************************"
    tyblue "beta版：就是测试版啦"
    tyblue "稳定版：就是稳定版啦"
    tyblue "LTS版：长期支持版本，可以理解为超级稳定版"
    tyblue "*************************注意事项*************************"
    tyblue "1.升级系统仅对ubuntu有效，非ubuntu系统将仅更新软件包"
    yellow "2.升级系统可能需要15分钟或更久"
    yellow "3.升级系统完成后将会重启，重启后，请再次运行此脚本完成剩余安装"
    yellow "4.有的时候不能一次性更新到所选择的版本，可能要更新两次，所以更新完"
    yellow "  第一次重启后，若还未升级到选定版本，请再选择相同的升级版本"
    yellow "5.升级过程中若有问话/对话框，如果看不懂，优先选择yes/y/第一个选项"
    yellow "6.若升级过程中与ssh断开连接，建议重置系统"
    yellow "7.升级系统后ssh超时时间将会恢复默认"
    tyblue "8.ubuntu20.04暂不支持bbr2"
    tyblue "**********************************************************"
    green  "您现在的系统版本是$systemVersion"
    tyblue "**********************************************************"
    echo
    updateconfig=5
    while [ "$updateconfig" != "1" -a "$updateconfig" != "2" -a "$updateconfig" != "3" ]
    do
        read -p "您的选择是：" updateconfig
    done
    yum -y update
    apt -y dist-upgrade
    apt -y --purge autoremove
    apt clean
    yum -y autoremove
    yum clean all
    echo '[DEFAULT]' > /etc/update-manager/release-upgrades
    echo 'Prompt=lts' >> /etc/update-manager/release-upgrades
    case "$updateconfig" in
        1)
            do-release-upgrade -d
            do-release-upgrade -d
            do-release-upgrade
            do-release-upgrade
            sed -i 's/Prompt=lts/Prompt=normal/' /etc/update-manager/release-upgrades
            do-release-upgrade -d
            do-release-upgrade
            ;;
        2)
            sed -i 's/Prompt=lts/Prompt=normal/' /etc/update-manager/release-upgrades
            do-release-upgrade
            do-release-upgrade
            ;;
        3)
            do-release-upgrade
            do-release-upgrade
            ;;
    esac
}


#升级系统组件
doupdate()
{
    echo -e "\n\n\n"
    tyblue "*******************是否将更新系统组件？*******************"
    if [ "$release" == "ubuntu" ]; then
        green  "1.更新已安装软件，并升级系统(仅对ubuntu有效)"
        green  "2.仅更新已安装软件"
        red    "3.不更新"
    else
        green  "1.仅更新已安装软件"
        red    "2.不更新"
    fi
    tyblue "**********************************************************"
    echo
    choice=""
    while [ "$choice" != "1" -a "$choice" != "2" -a "$choice" != "3" ]
    do
        read -p "您的选择是：" choice
    done
    if [[ "$release" == "ubuntu" && "$choice" == "1" ]] ; then
        updateSystem
    elif [[ "$release" == "ubuntu" && "$choice" == "2" || "$release" == "centos" && "$choice" == "1" ]]; then
        tyblue "***************即将开始更新已安装软件***************"
        yellow "更新过程中若有问话/对话框，如果看不懂，优先选择yes/y/第一个选项"
        yellow "按回车键继续。。。"
        read rubbish
        yum -y update
        apt -y dist-upgrade
        apt -y --purge autoremove
        apt clean
        yum -y autoremove
        yum clean all
    fi
    apt -y --purge autoremove
    apt clean
    yum -y autoremove
    yum clean all
}


#删除防火墙
uninstall_firewall()
{
    ufw disable
    #apt purge iptables -y
    apt -y purge firewalld ufw
    #chkconfig iptables off
    systemctl disable firewalld
    yum -y remove firewalld
    rm -rf /usr/local/aegis
    rm -rf /usr/local/cloudmonitor
    rm -rf /usr/sbin/aliyun-service
    #pkill wrapper.syslog.id
    #pkill wrapper
    pkill CmsGoAgent
    pkill aliyun-service
    service aegis stop
    #rm -rf /usr/bin/networkd-dispatcher
    #pkill networkd
    rm -rf /etc/init.d/aegis
}


#卸载v2ray和nginx
remove_v2ray_nginx()
{
    /etc/nginx/sbin/nginx -s stop
    service v2ray stop
    #service v2ray disable
    rm -rf /usr/bin/v2ray
    rm -rf /etc/v2ray
    rm -rf /etc/nginx
    is_installed=0
}


check_fake_version() {
    local temp=${1##*.}
    if [ ${temp} -eq 0 ] ; then
        return 0
    else
        return 1
    fi
}

#安装bbr
install_bbr()
{
    if ! grep -q "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" /etc/sysctl.conf ; then
        echo ' ' >> /etc/sysctl.conf
        echo "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" >> /etc/sysctl.conf
    fi
    kernel_version=`uname -r | cut -d - -f 1`
    while check_fake_version ${kernel_version} ;
    do
        kernel_version=${kernel_version%.*}
    done
    version=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/ | awk -F'\"v' '/v[0-9]/{print $2}' | cut -d '"' -f1 | cut -d '/' -f1 | sort -rV)
    last_v=$(echo $version | cut -d ' ' -f 1)
    if cat /etc/issue | grep -qi "ubuntu" || cat /proc/version | grep -qi "ubuntu" || cat /etc/issue | grep -Eqi "debian" || cat /proc/version | grep -Eqi "debian" ; then
        rc_version=`uname -r | cut -d - -f 2`
        if [[ $rc_version =~ "rc" ]] ; then
            rc_version=${rc_version##*'rc'}
            kernel_version=${kernel_version}-rc${rc_version}
        fi
        if [[ $last_v =~ "rc" ]] ; then
            last_v2=${last_v%%-*}
            if echo $version | grep -q " $last_v2 " ; then
                last_v=$last_v2
            fi
        fi
    else
        last_v=${last_v%%-*}
    fi
    echo -e "\n\n\n"
    tyblue "******************请选择要使用的bbr版本******************"
    green  "1.升级最新版内核并启用bbr(推荐)"
    tyblue "2.启用bbr(如果内核不支持，将自动升级内核)"
    yellow "3.启用bbr2(需安装第三方内核)(Ubuntu、Debian)"
    yellow "4.启用bbr2(需安装第三方内核)(Centos)"
    yellow "5.启用bbrplus/魔改版bbr/锐速(需安装第三方内核)"
    tyblue "6.退出bbr安装"
    tyblue "******************关于安装bbr加速的说明******************"
    green  "bbr加速可以大幅提升网络速度，建议安装"
    green  "新版本内核的bbr比旧版强得多，最新版本内核的bbr强于bbrplus等"
    yellow "安装第三方内核可能造成系统不稳定，甚至无法开机"
    yellow "安装内核需重启才能生效"
    yellow "重启后，请再次运行此脚本完成剩余安装"
    tyblue "*********************************************************"
    tyblue "当前内核版本：${kernel_version}"
    tyblue "最新内核版本：${last_v}"
    tyblue "当前内核是否支持bbr："
    if version_ge $kernel_version 4.9 ; then
        green "是"
    else
        red "否，需升级内核"
    fi
    tyblue "bbr启用状态："
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr ; then
        bbr_info=`sysctl net.ipv4.tcp_congestion_control`
        bbr_info=${bbr_info#*=}
        green "正在使用：${bbr_info}"
    else
        red "bbr未启用！！"
    fi
    bbrconfig=100
    while [ "$bbrconfig" != "1" -a "$bbrconfig" != "2" -a "$bbrconfig" != "3" -a "$bbrconfig" != "4" -a "$bbrconfig" != "5" -a "$bbrconfig" != "6" ]
    do
        read -p "您的选择是：" bbrconfig
    done
    case "$bbrconfig" in
        1)
            yellow "此操作将会尝试安装最新内核，并开启bbr"
            yellow "若无法安装最新版内核，可以尝试："
            yellow "1.使用更新版本的系统"
            yellow "2.选择2选项，或者使用bbr2/bbrplus"
            yellow "按回车键以继续。。。"
            read rubbish
            sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
            sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
            echo 'net.core.default_qdisc = fq' >> /etc/sysctl.conf
            echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
            sysctl -p
            rm -rf update-kernel.sh
            if ! wget https://github.com/kirin10000/V2Ray-WebSocket-TLS-Web-setup-script/raw/master/update-kernel.sh ; then
                red    "获取内核升级脚本失败"
                red    "你的服务器貌似没联网，或不支持ipv4"
                yellow "可以尝试一下修改DNS(搭建脚本里有这个选项)"
                yellow "按回车键继续或者按ctrl+c终止"
                read rubbish
            fi
            chmod +x update-kernel.sh
            ./update-kernel.sh
            if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr" ; then
                red "开启bbr失败！！"
                red "如果刚安装完内核，请先重启！！"
                red "如果重启仍然无效，请尝试选择2选项"
            else
                green "********************bbr已安装********************"
            fi
            install_bbr
            ;;
        2)
            sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
            sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
            echo 'net.core.default_qdisc = fq' >> /etc/sysctl.conf
            echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
            sysctl -p
            sleep 1s
            if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr" ; then
                rm -rf bbr.sh
                if ! wget https://github.com/teddysun/across/raw/master/bbr.sh ; then
                    red    "获取bbr脚本失败"
                    red    "你的服务器貌似没联网，或不支持ipv4"
                    yellow "可以尝试一下修改DNS(搭建脚本里有这个选项)"
                    yellow "按回车键继续或者按ctrl+c终止"
                    read rubbish
                fi
                chmod +x bbr.sh
                ./bbr.sh
            else
                green "********************bbr已安装********************"
            fi
            install_bbr
            ;;
        3)
            tyblue "*********************即将安装bbr2加速，安装完成后服务器将会重启*********************"
            tyblue "重启后，请再次选择这个选项完成bbr2剩余部分安装(开启bbr和ECN)"
            tyblue "目前已知支持bbr2系统：Ubuntu16.04 —— 19.10、Debian 8 9 10"
            red    "目前已知不支持bbr2系统：Ubuntu14.04 20.04"
            red    "警告：不支持的系统安装bbr2会导致系统崩溃(可正常安装bbr1)"
            yellow "按回车键以继续。。。。"
            read rubbish
            rm -rf bbr2.sh
            if ! wget https://github.com/yeyingorg/bbr2.sh/raw/master/bbr2.sh ; then
                red    "获取bbr2脚本失败"
                red    "你的服务器貌似没联网，或不支持ipv4"
                yellow "可以尝试一下修改DNS(搭建脚本里有这个选项)"
                yellow "按回车键继续或者按ctrl+c终止"
                read rubbish
            fi
            chmod +x bbr2.sh
            ./bbr2.sh
            install_bbr
            ;;
        4)
            rm -rf bbr2.sh
            if ! wget https://github.com/jackjieYYY/bbr2/raw/master/bbr2.sh ; then
                red    "获取bbr2脚本失败"
                yellow "你的服务器貌似没联网，或不支持ipv4"
                yellow "可以尝试一下修改DNS(搭建脚本里有这个选项)"
                yellow "按回车键继续或者按ctrl+c终止"
                read rubbish
            fi
            chmod +x bbr2.sh
            ./bbr2.sh
            install_bbr
            ;;
        5)
            rm -rf tcp.sh
            if ! wget "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh" ; then
                red    "获取bbrplus脚本失败"
                yellow "你的服务器貌似没联网，或不支持ipv4"
                yellow "可以尝试一下修改DNS(搭建脚本里有这个选项)"
                yellow "按回车键继续或者按ctrl+c终止"
                read rubbish
            fi
            chmod +x tcp.sh
            ./tcp.sh
            install_bbr
            ;;
    esac
    rm -rf bbr.sh
    rm -rf update-kernel.sh
    rm -rf tcp.sh
    rm -rf bbr2.sh
    rm -rf install_bbr.log*
}


#配置sshd
setsshd()
{
    echo
    tyblue "*****************************************"
    tyblue "安装可能需要比较长的时间(5-40分钟)"
    tyblue "如果和ssh断开连接将会很麻烦"
    tyblue "设置ssh连接超时时间将大大降低断连可能性"
    yellow "注：升级系统后ssh配置文件将会恢复默认"
    tyblue "*****************************************"
    ifsetsshd=9
    while [ "$ifsetsshd" != "y" -a "$ifsetsshd" != "n" ]
    do
        tyblue "是否设置ssh连接超时时间？(y/n)"
        read ifsetsshd
    done
    case "$ifsetsshd" in
        y)
            echo ' ' >> /etc/ssh/sshd_config
            echo "ClientAliveInterval 30" >> /etc/ssh/sshd_config
            echo "ClientAliveCountMax 60" >> /etc/ssh/sshd_config
            echo "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" >> /etc/ssh/sshd_config
            service sshd restart
            green  "**********************配置完成**********************"
            tyblue "请重新进行ssh连接，然后再次运行此脚本"
            yellow "按回车键退出。。。。"
            read asfyerbsd
            exit
            ;;
        n)
            ;;
    esac
}


#获取证书  参数：  doamin   domainconfig
get_certs()
{
    cp /etc/nginx/conf/nginx.conf.default /etc/nginx/conf/nginx.conf
    /etc/nginx/sbin/nginx -s stop
    sleep 1s
    /etc/nginx/sbin/nginx
    case "$2" in
        1)
            ~/.acme.sh/acme.sh --issue -d $1 -d www.$1 --webroot /etc/nginx/html -k ec-256 --ocsp
            ~/.acme.sh/acme.sh --issue -d $1 -d www.$1 --webroot /etc/nginx/html -k ec-256 --ocsp
            ;;
        2)
            ~/.acme.sh/acme.sh --issue -d $1 --webroot /etc/nginx/html -k ec-256 --ocsp
            ~/.acme.sh/acme.sh --issue -d $1 --webroot /etc/nginx/html -k ec-256 --ocsp
            ;;
    esac
    /etc/nginx/sbin/nginx -s stop
}



#安装程序主体
install_v2ray_ws_tls()
{
    if ! grep -q "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" /etc/ssh/sshd_config ; then
        setsshd
    fi
    apt -y -f install
    remove_v2ray_nginx
    apt update
    uninstall_firewall
    doupdate
    uninstall_firewall
    if ! grep -q "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" /etc/sysctl.conf ; then
        echo ' ' >> /etc/sysctl.conf
        echo "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv4.tcp_fastopen = 3" /etc/sysctl.conf || ! sysctl net.ipv4.tcp_fastopen | grep -q 3 ; then
        sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
        echo 'net.ipv4.tcp_fastopen = 3' >> /etc/sysctl.conf
        sysctl -p
    fi
    install_bbr
    apt -y -f install
    apt -y --purge autoremove
    yum -y autoremove
    #读取域名
    readDomain
    readTlsConfig
    yum install -y gperftools-devel libatomic_ops-devel pcre-devel zlib-devel libxslt-devel gd-devel perl-ExtUtils-Embed geoip-devel lksctp-tools-devel libxml2-devel gcc gcc-c++ wget unzip curl make
    ##libxml2-devel非必须
    if [ "$release" == "ubuntu" ] && version_ge $systemVersion 20.04; then
        apt -y install gcc-10 g++-10
        apt -y purge gcc g++ gcc-9 g++-9 gcc-8 g++-8 gcc-7 g++-7
        apt -y install gcc-10 g++-10
        apt -y autopurge
        ln -s -f /usr/bin/gcc-10 /usr/bin/gcc
        ln -s -f /usr/bin/gcc-10 /usr/bin/cc
        ln -s -f /usr/bin/g++-10 /usr/bin/g++
        ln -s -f /usr/bin/g++-10 /usr/bin/c++
        ln -s -f /usr/bin/gcc-10 /usr/bin/x86_64-linux-gnu-gcc
        ln -s -f /usr/bin/g++-10 /usr/bin/x86_64-linux-gnu-g++
    else
        apt -y install gcc g++
    fi
    apt install -y libgoogle-perftools-dev libatomic-ops-dev libperl-dev libxslt-dev zlib1g-dev libpcre3-dev libgeoip-dev libgd-dev libxml2-dev libsctp-dev wget unzip curl make
    ##libxml2-dev非必须
    apt -y --purge autoremove
    yum -y autoremove
    apt clean
    yum clean all


##安装nginx
    rm -rf ${nginx_version}.tar.gz
    rm -rf ${openssl_version}.tar.gz
    rm -rf $openssl_version
    rm -rf ${nginx_version}
    if ! wget -O ${nginx_version}.tar.gz https://nginx.org/download/${nginx_version}.tar.gz ; then
        red    "获取nginx失败"
        yellow "按回车键继续或者按ctrl+c终止"
        read rubbish
    fi
    tar -zxf ${nginx_version}.tar.gz
    if ! wget -O ${openssl_version}.tar.gz https://www.openssl.org/source/${openssl_version}.tar.gz ; then
        red    "获取openssl失败"
        yellow "按回车键继续或者按ctrl+c终止"
        read rubbish
    fi
    tar -zxf ${openssl_version}.tar.gz
    cd ${openssl_version}
    sed -i 's#"OpenSSL {- "$config{full_version} $config{release_date}" -}"#"OpenSSL {- "$config{full_version}" -}"#g' include/openssl/opensslv.h.in
    cd ..
    cd ${nginx_version}
    sed -i 's# -g # #g' `grep " \-g " -rl auto`
    sed -i 's# -g"# "#g' `grep " \-g\"" -rl auto`
    sed -i 's#-O #-O3 #g' `grep "\-O " -rl auto`
    sed -i 's#-O"#-O3"#g' `grep "\-O\"" -rl auto`
    sed -i 's#-O2#-O3#g' `grep "\-O2" -rl auto`
    sed -i 's#-O1#-O3#g' `grep "\-O1" -rl auto`
    sed -i 's#-Os#-O3#g' `grep "\-Os" -rl auto`
    sed -i 's#-Og#-O3#g' `grep "\-Og" -rl auto`
    sed -i 's#-Oz#-O3#g' `grep "\-Oz" -rl auto`
    sed -i s#\'-O\'#\'-O3\'#g src/http/modules/perl/Makefile.PL
    sed -i 's#-Werror# #g' `grep "\-Werror" -rl auto`
    ./configure --prefix=/etc/nginx --with-openssl=../$openssl_version --with-openssl-opt="enable-tls1_3 enable-tls1_2 enable-tls1 enable-ssl enable-ssl2 enable-ssl3 enable-ec_nistp_64_gcc_128 shared threads zlib-dynamic sctp" --with-mail=dynamic --with-mail_ssl_module --with-stream=dynamic --with-stream_ssl_module --with-stream_realip_module --with-stream_geoip_module=dynamic --with-stream_ssl_preread_module --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_geoip_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_auth_request_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-pcre --with-libatomic --with-compat --with-cpp_test_module --with-google_perftools_module --with-file-aio --with-threads --with-poll_module --with-select_module --with-cc-opt=-O3
    make
    make install
    mkdir /etc/nginx/conf.d
    mkdir /etc/nginx/tcmalloc_temp
    chmod 777 /etc/nginx/tcmalloc_temp
    cd ..
    rm -rf ${nginx_version}.tar.gz
    rm -rf ${openssl_version}.tar.gz
    rm -rf $openssl_version
    rm -rf ${nginx_version}
##安装nignx完成


    curl https://get.acme.sh | sh
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    get_certs $domain $domainconfig
    bash <(curl -L -s https://install.direct/go.sh)
    bash <(curl -L -s https://install.direct/go.sh)
    service v2ray stop


##获取端口、id和path
    get_base_information
##配置nginx
    configtls $domain $tlsVersion $domainconfig $path $port $pretend
##配置v2ray文件
    config_v2ray_vmess

    get_web $domain $pretend

    service v2ray start
    /etc/nginx/sbin/nginx
    curl --tcp-fastopen https://127.0.0.1 >> /dev/null 2>&1   #激活tcp_fast_open
    curl --tcp-fastopen https://127.0.0.1 >> /dev/null 2>&1
    echo -e "\n\n\n"
    tyblue "*************安装完成*************"
    if [ $domainconfig -eq 1  ]; then
        tyblue "地址：www.${domain}或${domain}"
    else
        tyblue "地址：${domain}"
    fi
    tyblue "端口：443"
    tyblue "用户ID：${v2id}"
    tyblue "额外ID：0"
    tyblue "加密方式：一般情况推荐none;若使用了cdn，推荐auto"
    tyblue "传输协议：ws"
    tyblue "伪装类型：none"
    tyblue "伪装域名：空"
    tyblue "路径：${path}"
    tyblue "底层传输安全：tls"
    tyblue "**********************************"
    yellow "注意事项：如重新启动服务器，请执行/etc/nginx/sbin/nginx"
    yellow "          或运行脚本，选择重启服务选项"
    echo
    if [ $pretend -eq 2 ]; then
        tyblue "如果要更换被镜像的网站"
        tyblue "修改/etc/nginx/conf.d/v2ray.conf"
        tyblue "将v.qq.com修改为你要镜像的网站"
    fi
    echo
    tyblue "脚本最后更新时间：2020.04.24"
    echo
    red    "此脚本仅供交流学习使用，请勿使用此脚本行违法之事。网络非法外之地，行非法之事，必将接受法律制裁!!!!"
    tyblue "2019.11"
}

#配置v2ray_vmess
config_v2ray_vmess()
{
cat > /etc/v2ray/config.json <<EOF
{
  "inbounds": [
    {
      "port": $port,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$v2id",
            "level": 1,
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$path"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
}

#配置v2ray_socks
config_v2ray_socks()
{
cat > /etc/v2ray/config.json <<EOF
{
  "inbounds": [
    {
      "port": $port,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": false,
        "userLevel": 10
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$path"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
}

#修改dns
change_dns()
{
    red    "注意！！"
    red    "1.部分云服务商(如阿里云)使用本地服务器作为软件包源，修改dns后需要换源！！"
    red    "  如果听不懂，那么请在安装完v2ray+ws+tls后再修改dns，并且修改完后不要重新安装"
    red    "2.Ubuntu系统重启后可能会恢复原dns"
    tyblue "此操作将修改dns服务器为1.1.1.1和1.0.0.1(cloudflare公共dns)"
    if_change_dns="45"
    while [ "$if_change_dns" != "y" -a "$if_change_dns" != "n" ]
    do
        tyblue "是否要继续?(y/n)"
        read if_change_dns
    done
    if [ $if_change_dns == "y" ]; then
        if ! grep -q "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" /etc/resolv.conf ; then
            sed -i 's/nameserver /#&/' /etc/resolv.conf
            echo ' ' >> /etc/resolv.conf
            echo 'nameserver 1.1.1.1' >> /etc/resolv.conf
            echo 'nameserver 1.0.0.1' >> /etc/resolv.conf
            echo '#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script' >> /etc/resolv.conf
        fi
        green "修改完成！！"
    fi
}


#获取信息
get_base_information()
{
    if [ "$is_installed" == "1" ]; then
        path=`grep path /etc/v2ray/config.json`
        path=${path##*' '}
        path=${path#*'"'}
        path=${path%'"'*}
        if grep -m 1 "ssl_protocols" /etc/nginx/conf.d/v2ray.conf | grep -q "TLSv1.2" ; then
            tlsVersion=1
        else
            tlsVersion=2
        fi
        domain_list=`grep -m 1 server_name /etc/nginx/conf.d/v2ray.conf`
        domain_list=${domain_list#*"server_name "}
        domain_list=(${domain_list%;*})
    else
        path=$(cat /dev/urandom | head -c 8 | md5sum | head -c 6)
        path="/$path"
    fi
    port=`grep port /etc/v2ray/config.json`
    port=${port##*' '}
    port=${port%%,*}
    if grep -q "id" /etc/v2ray/config.json ; then
        v2id=`grep id /etc/v2ray/config.json`
        v2id=${v2id##*' '}
        v2id=${v2id#*'"'}
        v2id=${v2id%'"'*}
    else
        v2id=""
    fi
}

#下载nextcloud模板，用于伪装  参数： domain  pretend
get_web()
{
    rm -rf /etc/nginx/html/$1
    if [ $2 -eq 3 ]; then
        mkdir /etc/nginx/html/$1
        if ! wget -P /etc/nginx/html/$1 https://github.com/kirin10000/V2ray-WebSocket-TLS-Web-setup-script/raw/master/Website-Template.zip ; then
            red    "获取网站模板失败"
            red    "你的服务器貌似没联网，或不支持ipv4"
            yellow "按回车键继续或者按ctrl+c终止"
            read asfyerbsd
        fi
        unzip -q -d /etc/nginx/html/$1 /etc/nginx/html/$1/*.zip
        rm -rf /etc/nginx/html/$1/*.zip
    fi
}

#使用vmess作为底层协议
back_to_vmess()
{
    if_back_to_vmess=""
    while [ "$if_back_to_vmess" != "y" -a "$if_back_to_vmess" != "n" ]
    do
        tyblue "返回vmess作为底层协议?(y/n)"
        read if_back_to_vmess
    done
    if [ $if_back_to_vmess == "n" ]; then
        exit 0;
    fi
    get_info
    v2id=`cat /proc/sys/kernel/random/uuid`
    config_v2ray_vmess
    service v2ray restart
    green "配置完成！！！"
    green "用户ID：$v2id"
}

#使用socks作为底层协议
turn_to_socks()
{
    tyblue "此操作将会把底层协议修改为socks(5)"
    tyblue "关于这么做的意义，参考https://github.com/v2ray/discussion/issues/513"
    if_turn_to_socks="45"
    while [ "$if_turn_to_socks" != "y" -a "$if_turn_to_socks" != "n" ]
    do
        tyblue "是否要继续?(y/n)"
        read if_turn_to_socks
    done
    if [ $if_turn_to_socks == "n" ]; then
        exit 0;
    fi
    get_info
    config_v2ray_socks
    service v2ray restart
    green  "配置完成！！！"
    tyblue "将下面一段文字复制下来，保存到文本文件中"
    tyblue "将“你的域名”四个字修改为你的其中一个域名(保留引号)，即原配置中“地址”一栏怎么填，这里就怎么填"
    tyblue "并将文本文件重命名为config.json"
    tyblue "然后在V2RayN/V2RayNG中，选择导入自定义配置，选择config.json"
    yellow "******************以下是文本******************"
cat <<EOF
{
  "log": {
    "access": "",
    "error": "",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10808,
      "protocol": "socks",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "settings": {
        "auth": "noauth",
        "userLevel": 10,
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "socks",
      "settings": {
        "servers": [
          {
            "address": "你的域名",
            "level": 10,
            "port": 443
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "wsSettings": {
          "path": "$path"
        }
      },
      "mux": {
        "enabled": true,
        "concurrency": 8
      }
    }
  ]
}
EOF
}

#开始菜单
start_menu()
{
    clear
    tyblue "-------------- V2Ray WebSocket(ws)+TLS(1.3)+Web 搭建/管理脚本--------------"
    tyblue "官网：https://github.com/kirin10000/V2Ray-WebSocket-TLS-Web-setup-script"
    tyblue "---------------------------------------------------------------------------"
    yellow "此脚本需要一个解析到本服务器的域名!!!!"
    tyblue "推荐服务器系统使用Ubuntu最新版"
    yellow "部分ssh工具会出现退格键无法使用问题，建议先保证退格键正常，再安装"
    yellow "测试退格键正常方法：按一下退格键，不会出现奇怪的字符即为正常"
    yellow "若退格键异常可以选择选项16修复"
    tyblue "---------------------------------------------------------------------------"
    tyblue "-----------安装/升级/卸载-----------"
    green  "1.安装/重新安装V2Ray-WebSocket+TLS+Web"
    green  "2.升级V2Ray-WebSocket+TLS+Web"
    tyblue "3.仅升级V2Ray"
    red    "4.卸载V2Ray-WebSocket+TLS+Web"
    tyblue "5.仅安装bbr(包含bbr2/bbrplus/魔改版bbr/锐速)"
    tyblue "6.升级证书"
    tyblue "7.强制升级证书"
    tyblue "--------------启动/停止-------------"
    tyblue "8.重启/启动V2Ray-WebSocket+TLS+Web(对于玄学断连/掉速有奇效)"
    tyblue "9.停止V2Ray-WebSocket+TLS+Web"
    tyblue "----------------管理----------------"
    tyblue "10.重置域名和TLS配置"
    tyblue "  (会覆盖原有域名配置，配置过程中域名输错了造成V2Ray无法启动可以用此选项修复)"
    tyblue "11.添加域名"
    tyblue "12.删除域名"
    if [ ! -e /etc/v2ray/config.json ] || grep -q "id" /etc/v2ray/config.json >> /dev/null 2>&1 ; then
        tyblue "13.使用socks(5)作为底层传输协议(降低计算量、延迟)(beta)"
    else
        tyblue "13.返回vmess作为底层传输协议"
    fi
    tyblue "14.查看/修改用户ID(id)"
    tyblue "15.查看/修改路径(path)"
    tyblue "----------------其它----------------"
    tyblue "16.尝试修复退格键无法使用的问题"
    tyblue "17.修改dns"
    yellow "18.退出脚本"
    echo
    choice=""
    while [[ "$choice" != "1" && "$choice" != "2" && "$choice" != "3" && "$choice" != "4" && "$choice" != "5" && "$choice" != "6" && "$choice" != "7" && "$choice" != "8" && "$choice" != "9" && "$choice" != "10" && "$choice" != "11" && "$choice" != "12" && "$choice" != "13" && "$choice" != "14" && "$choice" != "15" && "$choice" != "16" && "$choice" != "17" && "$choice" != "18" ]]
    do
        read -p "您的选择是：" choice
    done
    case "$choice" in
        1)
            install_v2ray_ws_tls
            ;;
        2)
            echo
            yellow "尝试修复退格键异常问题，退格键正常请不要修复"
            yellow "按回车键继续或按Ctrl+c退出"
            read -s rubbish
            if stty -a | grep -q 'erase = ^?' ; then
                stty erase '^H'
            elif stty -a | grep -q 'erase = ^H' ; then
                stty erase '^?'
            fi
            green "修复完成！！"
            sleep 1s
            start_menu
            ;;
        3)
            choice=""
            while [ "$choice" != "y" -a "$choice" != "n" ]
            do
                yellow "删除V2Ray-WebSocket(ws)+TLS(1.3)+Web?(y/n)"
                read choice
            done
            if [ "$choice" == "n" ]; then
                exit 0
            fi
            remove_v2ray_nginx
            green  "v2ray-WebSocket(ws)+TLS(1.3)+Web已删除"
            ;;
        4)
            /etc/nginx/sbin/nginx -s stop
            service v2ray stop
            sleep 1s
            service v2ray start
            /etc/nginx/sbin/nginx
            curl --tcp-fastopen https://127.0.0.1 >> /dev/null 2>&1   #激活tcp_fast_open
            curl --tcp-fastopen https://127.0.0.1 >> /dev/null 2>&1
            green  "重启完成"
            ;;
        5)
            readDomain
            readTlsConfig
            get_certs
            get_info
            configtls
            get_web
            /etc/nginx/sbin/nginx
            green "重置域名完成！！"
            case "$domainconfig" in
                1)
                    green "服务器地址请填写www.${domain} 或 $domain"
                    ;;
                2)
                    green "服务器地址请填写$domain"
                    ;;
            esac
            echo
            if [ $pretend -eq 2 ]; then
                tyblue "如果要更换被镜像的网站"
                tyblue "修改/etc/nginx/conf.d/v2ray.conf"
                tyblue "将v.qq.com修改为你要镜像的网站"
            fi
            ;;
        6)
            readDomain
            new_domain $domain $domainconfig $pretend
            green "添加域名完成！！"
            case "$domainconfig" in
                1)
                    green "现在服务器地址可以填写原来的域名和www.${domain} ${domain}"
                    ;;
                2)
                    green "现在服务器地址可以填写原来的域名和${domain}"
                    ;;
            esac
            echo
            if [ $pretend -eq 2 ]; then
                tyblue "如果要更换被镜像的网站"
                tyblue "修改/etc/nginx/conf.d/v2ray.conf"
                tyblue "将v.qq.com修改为你要镜像的网站"
            fi
            ;;
        7)
            if [ ! -e /etc/v2ray/config.json ] || [ ! -e /etc/nginx ] ; then
                red "请先安装V2Ray-WebSocket(ws)+TLS(1.3)+Web！！"
                exit 1;
            fi
            if grep -q "id" /etc/v2ray/config.json ; then
                turn_to_socks
            else
                back_to_vmess
            fi
            ;;
        8)
            if [ ! -e /etc/v2ray/config.json ] ; then
                red "请先安装V2Ray-WebSocket(ws)+TLS(1.3)+Web！！"
                exit 1;
            fi
            if ! grep -q "id" /etc/v2ray/config.json ; then
                red "socks模式没有ID！！"
                exit 1;
            fi
            get_info
            tyblue "您现在的ID是：$v2id"
            if_change_id="45"
            while [ "$if_change_id" != "y" -a "$if_change_id" != "n" ]
            do
                tyblue "是否要继续?(y/n)"
                read if_change_id
            done
            if [ $if_change_id == "n" ]; then
                exit 0;
            fi
            tyblue "*****************请输入新的ID*****************"
            read new_v2id
            sed -i s/"$v2id"/"$new_v2id"/ /etc/v2ray/config.json
            service v2ray restart
            green "更换成功！！"
            green "新ID：$new_v2id"
            ;;
        9)
            if [ ! -e /etc/v2ray/config.json ] || [ ! -e /etc/nginx ] ; then
                red "请先安装V2Ray-WebSocket(ws)+TLS(1.3)+Web！！"
                exit 1;
            fi
            get_info
            tyblue "您现在的path是：$path"
            if_change_path="45"
            while [ "$if_change_path" != "y" -a "$if_change_path" != "n" ]
            do
                tyblue "是否要继续?(y/n)"
                read if_change_path
            done
            if [ $if_change_path == "n" ]; then
                exit 0;
            fi
            tyblue "*****************请输入新的path(带\"/\")*****************"
            read new_path
            sed -i s#"$path"#"$new_path"# /etc/v2ray/config.json
            sed -i s#"$path"#"$new_path"# /etc/nginx/conf.d/v2ray.conf
            service v2ray restart
            /etc/nginx/sbin/nginx -s stop
            sleep 1s
            /etc/nginx/sbin/nginx
            green "更换成功！！"
            green "新path：$new_path"
            ;;
        10)
            apt -y -f install
            install_bbr
            ;;
        11)
            change_dns
            ;;
        12)
            if ! bash <(curl -L -s https://install.direct/go.sh) ; then
                red    "你的服务器貌似没联网，或不支持ipv4，请检查网络连接"
                yellow "v2ray更新失败"
            fi
            ;;
    esac
}


start_menu                                     ##从这里脚本开始执行
