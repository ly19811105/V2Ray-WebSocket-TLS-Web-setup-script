#!/usr/bin/env bash
#
# Auto install latest kernel for TCP BBR
#
# System Required:  CentOS 6+, Debian7+, Ubuntu12+
#
# Copyright (C) 2016-2018 Teddysun <i@teddysun.com>
#
# URL: https://teddysun.com/489.html
#

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

[[ $EUID -ne 0 ]] && echo -e "${red}Error:${plain} This script must be run as root!" && exit 1

[[ -d "/proc/vz" ]] && echo -e "${red}Error:${plain} Your VPS is based on OpenVZ, which is not supported." && exit 1

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
else
    release=""
fi

is_digit(){
    local input=${1}
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

is_64bit(){
    if [ $(getconf WORD_BIT) = '32' ] && [ $(getconf LONG_BIT) = '64' ]; then
        return 0
    else
        return 1
    fi
}

get_valid_valname(){
    local val=${1}
    local new_val=$(eval echo $val | sed 's/[-.]/_/g')
    echo ${new_val}
}

get_hint(){
    local val=${1}
    local new_val=$(get_valid_valname $val)
    eval echo "\$hint_${new_val}"
}

#Display Memu
display_menu(){
    local soft=${1}
    local default=${2}
    eval local arr=(\${${soft}_arr[@]})
    local default_prompt
    if [[ "$default" != "" ]]; then
        if [[ "$default" == "last" ]]; then
            default=${#arr[@]}
        fi
        default_prompt="(default ${arr[$default-1]})"
    fi
    local pick
    local hint
    local vname
    local prompt="which ${soft} you'd select ${default_prompt}: "

    while :
    do
        #echo -e "\n------------ ${soft} setting ------------\n"
        for ((i=1;i<=${#arr[@]};i++ )); do
            vname="$(get_valid_valname ${arr[$i-1]})"
            hint="$(get_hint $vname)"
            [[ "$hint" == "" ]] && hint="${arr[$i-1]}"
            #echo -e "${green}${i}${plain}) $hint"
        done
        echo
        #read -p "${prompt}" pick
        pick=${#arr[@]}
        if [[ "$pick" == "" && "$default" != "" ]]; then
            pick=${default}
            break
        fi

        if ! is_digit "$pick"; then
            prompt="Input error, please input a number"
            continue
        fi

        if [[ "$pick" -lt 1 || "$pick" -gt ${#arr[@]} ]]; then
            prompt="Input error, please input a number between 1 and ${#arr[@]}: "
            continue
        fi

        break
    done

    eval ${soft}=${arr[$pick-1]}
    vname="$(get_valid_valname ${arr[$pick-1]})"
    hint="$(get_hint $vname)"
    [[ "$hint" == "" ]] && hint="${arr[$pick-1]}"
    echo -e "\nyour selection: $hint\n"
}

version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

failed_version()
{
    if [[ `getconf WORD_BIT` == "32" && `getconf LONG_BIT` == "64" ]]; then
        deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${1}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
    else
        deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${1}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
    fi
    if [ -z ${deb_name} ]; then
        return 0
    else
        return 1
    fi
}

last_version()
{
    if [ "$kernel" != "${kernel_list[kernel_i]}" ]; then
        kernel=${kernel_list[kernel_i]}
        return 0
    fi
    ((kernel_i++))
    if ! [[ "$kernel" =~ "rc" ]] && [[ "${kernel_list[kernel_i]}" =~ "rc" ]]; then
        if check_rc2 ${kernel_list[kernel_i]}; then
            kernel=${kernel_list[kernel_i]%%-*}
            return 0
        fi
    fi
    if [[ "$kernel" =~ "rc" ]] && [[ "${kernel_list[kernel_i]}" =~ "rc" ]]; then
        if [ "${kernel%%-*}" != "${kernel_list[kernel_i]%%-*}" ]; then
            if check_rc2 ${kernel_list[kernel_i]}; then
                kernel=${kernel_list[kernel_i]%%-*}
                return 0
            fi
        fi
    fi
    if [[ "$kernel" =~ "rc" ]] && ! [[ "${kernel_list[kernel_i]}" =~ "rc" ]]; then
        if [ "${kernel_list[kernel_i]}" == ${kernel%%-*} ]; then
            ((kernel_i++))
        fi
    fi
    kernel=${kernel_list[kernel_i]}
}

check_rc2()
{
    if [[ "${1}" =~ "rc" ]] ; then
        local temp=${1%%-*}
        if echo ${kernel_list[@]} | grep -q " ${temp} " ; then
            return 0
        fi
    fi
    return 1
}

get_latest_version() {
    kernel_list=($(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/ | awk -F'\"v' '/v[0-9]/{print $2}' | cut -d '"' -f1 | cut -d '/' -f1 | sort -rV))
    kernel_i=0
    kernel=${kernel_list[kernel_i]}
    if check_rc2 ${kernel}; then
        kernel=${kernel%%-*}
    fi
    while failed_version $kernel ;
    do
        last_version
    done
    echo "latest_kernel_version=$kernel"
    #[ ${#latest_version[@]} -eq 0 ] && echo -e "${red}Error:${plain} Get latest kernel version failed." && exit 1

    #kernel_arr=()
    #for i in ${latest_version[@]}; do
    #    if version_ge $i 4.14; then
    #        kernel_arr+=($i);
    #    fi
    #done

    #display_menu kernel last

    if [[ `getconf WORD_BIT` == "32" && `getconf LONG_BIT` == "64" ]]; then
        deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${deb_name}"
        deb_kernel_name="linux-image-${kernel}-amd64.deb"
        headers_all_deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-headers" | grep "all" | awk -F'\">' '/.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_headers_all_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${headers_all_deb_name}"
        headers_generic_deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-headers" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_headers_generic_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${headers_generic_deb_name}"
        modules_deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-modules" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_modules_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${modules_deb_name}"
        deb_kernel_modules_name="linux-modules-${kernel}-amd64.deb"
    else
        headers_all_deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-headers" | grep "all" | awk -F'\">' '/.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_headers_all_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${headers_all_deb_name}"
        headers_generic_deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-headers" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_headers_generic_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${headers_generic_deb_name}"
        deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${deb_name}"
        deb_kernel_name="linux-image-${kernel}-i386.deb"
        modules_deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-modules" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_modules_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${modules_deb_name}"
        deb_kernel_modules_name="linux-modules-${kernel}-i386.deb"
    fi

    [ -z ${deb_name} ] && echo -e "${red}Error:${plain} Getting Linux kernel binary package name failed, maybe kernel build failed. Please choose other one and try again." && exit 1
}

get_opsy() {
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

opsy=$( get_opsy )
arch=$( uname -m )
lbit=$( getconf LONG_BIT )
kern=$( uname -r )

get_char() {
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

getversion() {
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

centosversion() {
    if [ x"${release}" == x"centos" ]; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

check_bbr_status() {
    local param=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    if [[ x"${param}" == x"bbr" ]]; then
        return 0
    else
        return 1
    fi
}
check_fake_version() {
    local temp=${1##*.}
    if [ ${temp} -eq 0 ] ; then
        return 0
    else
        return 1
    fi
}
check_kernel_version() {
    local kernel_version=$(uname -r | cut -d - -f 1)
    while check_fake_version ${kernel_version} ;
    do
        kernel_version=${kernel_version%.*}
    done
    if [[ x"${release}" == x"ubuntu" || x"${release}" == x"debian" ]] ; then
        rc_version=`uname -r | cut -d - -f 2`
        if [[ $rc_version =~ "rc" ]] ; then
            rc_version=${rc_version##*'rc'}
            kernel_version=${kernel_version}-rc${rc_version}
        fi
    fi
    echo "your_kernel_version=${kernel_version}"
    if [[ $kernel_version =~ "rc" ]] ; then
        if ! [[ $kernel =~ "rc" ]] ; then
            return 1
        fi
    fi
    if version_ge ${kernel_version} ${kernel}; then
        return 0
    else
        return 1
    fi
}

install_elrepo() {

    if centosversion 5; then
        echo -e "${red}Error:${plain} not supported CentOS 5."
        exit 1
    fi

    rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org

    if centosversion 6; then
        yum install -y https://www.elrepo.org/elrepo-release-6-9.el6.elrepo.noarch.rpm
    elif centosversion 7; then
        yum install -y https://www.elrepo.org/elrepo-release-7.0-4.el7.elrepo.noarch.rpm
    elif centosversion 8; then
        yum install -y https://www.elrepo.org/elrepo-release-8.0-2.el8.elrepo.noarch.rpm
    fi

    if [ ! -f /etc/yum.repos.d/elrepo.repo ]; then
        echo -e "${red}Error:${plain} Install elrepo failed, please check it."
        exit 1
    fi
}

sysctl_config() {
    if ! grep -q "#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script" /etc/sysctl.conf ; then
        sed -i 's/net.ipv4.tcp_congestion_control/#&/' /etc/sysctl.conf
        echo ' ' >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
        echo '#This file has been edited by v2ray-WebSocket-TLS-Web-setup-script' >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
}

install_config() {
    if [[ x"${release}" == x"centos" ]]; then
        if centosversion 6; then
            if [ ! -f "/boot/grub/grub.conf" ]; then
                echo -e "${red}Error:${plain} /boot/grub/grub.conf not found, please check it."
                exit 1
            fi
            sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
        elif centosversion 7; then
            if [ ! -f "/boot/grub2/grub.cfg" ]; then
                echo -e "${red}Error:${plain} /boot/grub2/grub.cfg not found, please check it."
                exit 1
            fi
            grub2-set-default 0
        fi
    elif [[ x"${release}" == x"debian" || x"${release}" == x"ubuntu" ]]; then
        /usr/sbin/update-grub
    fi
}

reboot_os() {
    echo
    echo -e "${green}Info:${plain} The system needs to reboot."
    read -p "Do you want to restart system? [y/n]" is_reboot
    if [[ ${is_reboot} == "y" || ${is_reboot} == "Y" ]]; then
        reboot
    else
        echo -e "${green}Info:${plain} Reboot has been canceled..."
        exit 0
    fi
}

install_bbr() {
    #apt update
    #apt install -y libssl-dev
    [[ ! -e "/usr/bin/wget" ]] && apt -y update && apt -y install wget

    if [[ x"${release}" == x"centos" ]]; then
        install_elrepo
        [ ! "$(command -v yum-config-manager)" ] && yum install -y yum-utils > /dev/null 2>&1
        [ x"$(yum-config-manager elrepo-kernel | grep -w enabled | awk '{print $3}')" != x"True" ] && yum-config-manager --enable elrepo-kernel > /dev/null 2>&1
        if centosversion 6; then
            echo "Centos 6太老了，不能更新最新内核，只能更新到4.18.20"
            if_continue=""
            while [ "$if_continue" != "y" -a "$if_continue" != "n" ]
            do
                read -p "是否要继续？(y/n)" if_continue
            done
            if [ $if_continue == "n" ] ; then
                exit 0
            fi
            if is_64bit; then
                rpm_kernel_name="kernel-ml-4.18.20-1.el6.elrepo.x86_64.rpm"
                rpm_kernel_devel_name="kernel-ml-devel-4.18.20-1.el6.elrepo.x86_64.rpm"
                rpm_kernel_url_1="http://repos.lax.quadranet.com/elrepo/archive/kernel/el6/x86_64/RPMS/"
            else
                rpm_kernel_name="kernel-ml-4.18.20-1.el6.elrepo.i686.rpm"
                rpm_kernel_devel_name="kernel-ml-devel-4.18.20-1.el6.elrepo.i686.rpm"
                rpm_kernel_url_1="http://repos.lax.quadranet.com/elrepo/archive/kernel/el6/i386/RPMS/"
            fi
            rpm_kernel_url_2="https://dl.lamp.sh/files/"
            wget -c -t3 -T60 -O ${rpm_kernel_name} ${rpm_kernel_url_1}${rpm_kernel_name}
            if [ $? -ne 0 ]; then
                rm -rf ${rpm_kernel_name}
                wget -c -t3 -T60 -O ${rpm_kernel_name} ${rpm_kernel_url_2}${rpm_kernel_name}
            fi
            wget -c -t3 -T60 -O ${rpm_kernel_devel_name} ${rpm_kernel_url_1}${rpm_kernel_devel_name}
            if [ $? -ne 0 ]; then
                rm -rf ${rpm_kernel_devel_name}
                wget -c -t3 -T60 -O ${rpm_kernel_devel_name} ${rpm_kernel_url_2}${rpm_kernel_devel_name}
            fi
            if [ -f "${rpm_kernel_name}" ]; then
                rpm -ivh ${rpm_kernel_name}
            else
                echo -e "${red}Error:${plain} Download ${rpm_kernel_name} failed, please check it."
                exit 1
            fi
            if [ -f "${rpm_kernel_devel_name}" ]; then
                rpm -ivh ${rpm_kernel_devel_name}
            else
                echo -e "${red}Error:${plain} Download ${rpm_kernel_devel_name} failed, please check it."
                exit 1
            fi
            rm -f ${rpm_kernel_name} ${rpm_kernel_devel_name}
        elif centosversion 7; then
            yum -y install kernel-ml kernel-ml-devel
            if [ $? -ne 0 ]; then
                echo -e "${red}Error:${plain} Install latest kernel failed, please check it."
                exit 1
            fi
        elif centosversion 8; then
            yum -y install kernel-ml kernel-ml-devel
            if [ $? -ne 0 ]; then
                echo -e "${red}Error:${plain} Install latest kernel failed, please check it."
                exit 1
            fi
        fi
    elif [[ x"${release}" == x"ubuntu" || x"${release}" == x"debian" ]]; then
        echo -e "${green}Info:${plain} Getting latest kernel version..."
        get_latest_version
        check_kernel_version
        if [ $? -eq 0 ]; then
            echo
            echo -e "${green}Info:${plain} Your kernel version is lastest"
            exit 0
        fi
        rm -rf kernel_
        mkdir kernel_
        cd kernel_
        systemVersion=`lsb_release -r --short`
        if [[ x"${release}" == x"ubuntu" ]] ; then
            if version_ge $systemVersion 18.04 ; then
                wget ${deb_kernel_headers_all_url}
                wget ${deb_kernel_headers_generic_url}
                flag=1
            fi
        else
            if version_ge $systemVersion 10 ; then
                wget ${deb_kernel_headers_all_url}
                wget ${deb_kernel_headers_generic_url}
                flag=1
            fi
        fi
        wget ${deb_kernel_url}
        wget ${deb_kernel_modules_url}
        dpkg -i *
        cd ..
        rm -rf kernel_
        apt -y -f install
        remove_kernel
    else
        echo -e "${red}Error:${plain} OS is not be supported, please change to CentOS/Debian/Ubuntu and try again."
        exit 1
    fi
    install_config
    #sysctl_config
    reboot_os
}

remove_kernel()
{
    while [ "$auto_remove" != "y" -a "$auto_remove" != "n" ]
    do
        read -p "是否卸载多余内核？(y/n)" auto_remove
    done
    if [ "$auto_remove" == "n" ]; then
        return 0
    fi
    kernel_list_headers=($(dpkg --list | grep 'linux-headers' | awk '{print $2}'))
    kernel_list_image=($(dpkg --list | grep 'linux-image' | awk '{print $2}'))
    kernel_list_modules=($(dpkg --list | grep 'linux-modules' | awk '{print $2}'))
    kernel_headers_all=${headers_all_deb_name%%_*}
    kernel_headers=${headers_generic_deb_name%%_*}
    kernel_image=${deb_name%%_*}
    kernel_modules=${modules_deb_name%%_*}


    if [ "$flag" == "1" ]; then

        ok_install=0
        for ((i=${#kernel_list_headers[@]}-1;i>=0;i--))
        do
            if [[ "${kernel_list_headers[$i]}" =~ "$kernel_headers" ]] ; then     
                kernel_list_headers[$i]=""
                ((ok_install++))
            fi
        done
        if [ "$ok_install" != "1" ] ; then
            echo "内核可能安装失败！不卸载"
            return 1
        fi



        ok_install=0
        for ((i=${#kernel_list_headers[@]}-1;i>=0;i--))
        do
            if [[ "${kernel_list_headers[$i]}" =~ "$kernel_headers_all" ]] ; then     
                kernel_list_headers[$i]=""
                ((ok_install++))
            fi
        done
        if [ "$ok_install" != "1" ] ; then
            echo "内核可能安装失败！不卸载"
            return 1
        fi
    fi




    ok_install=0
    for ((i=${#kernel_list_headers[@]}-1;i>=0;i--))
    do
        if [[ "${kernel_list_image[$i]}" =~ "$kernel_image" ]] ; then     
            kernel_list_image[$i]=""
            ((ok_install++))
        fi
    done
    if [ "$ok_install" != "1" ] ; then
        echo "内核可能安装失败！不卸载"
        return 1
    fi




    ok_install=0
    for ((i=${#kernel_list_headers[@]}-1;i>=0;i--))
    do
        if [[ "${kernel_list_modules[$i]}" =~ "$kernel_modules" ]] ; then     
            kernel_list_modules[$i]=""
            ((ok_install++))
        fi
    done
    if [ "$ok_install" != "1" ] ; then
        echo "内核可能安装失败！不卸载"
        return 1
    fi



    if [ "$flag" == "1" ]; then
        apt -y purge ${kernel_list_headers[@]} ${kernel_list_image[@]} ${kernel_list_modules[@]}
        apt -y remove ${kernel_list_headers[@]} ${kernel_list_image[@]} ${kernel_list_modules[@]}
    else
        apt -y purge ${kernel_list_image[@]} ${kernel_list_modules[@]}
        apt -y remove ${kernel_list_image[@]} ${kernel_list_modules[@]}
    fi
    apt -y -f install
}

clear
echo "---------- System Information ----------"
echo " OS      : $opsy"
echo " Arch    : $arch ($lbit Bit)"
echo " Kernel  : $kern"
echo "----------------------------------------"
echo " Auto install latest kernel"
echo
echo " URL: https://teddysun.com/489.html"
echo "----------------------------------------"
echo "     更       新       内       核"
echo "Press any key to start...or Press Ctrl+C to cancel"
char=`get_char`

install_bbr 2>&1
