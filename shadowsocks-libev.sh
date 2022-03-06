#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS/Debian/Ubuntu
#	Description: Shadowsocks libev
#	Author: 佩佩
#	WebSite: https://www.nange.cn
#=================================================

sh_ver="1.2.4"
filepath=$(cd "$(dirname "$0")"; pwd)
file_1=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
FOLDER="/etc/shadowsocks-libev"
FILE="/usr/local/bin/ss-server"
CONF="/etc/shadowsocks-libev/config.json"
Now_ver_File="/etc/shadowsocks-libev/ver.txt"
Local="/etc/sysctl.d/local.conf"

libsodium_file="libsodium-1.0.18"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz"

mbedtls_file='mbedtls-2.16.6'
mbedtls_url='https://tls.mbed.org/download/'"$mbedtls_file"'-apache.tgz'

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m" && Yellow_font_prefix="\033[0;33m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Yellow_font_prefix}[注意]${Font_color_suffix}"

install_libsodium() {
    if [ ! -f /usr/lib/libsodium.a ]; then
		wget --no-check-certificate -cq -t3 -T60 -O "${libsodium_file}.tar.gz" "${libsodium_url}"
        tar -xzf ${libsodium_file}.tar.gz
        cd ${libsodium_file} || exit
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "${Error} ${libsodium_file} 安装失败！"
            exit 1
        fi
    else
        echo -e "${Info} ${libsodium_file} 已经安装！"
    fi
}

install_mbedtls() {
    if [ ! -f /usr/lib/libmbedtls.a ]; then
		wget --no-check-certificate -cq -t3 -T60 -O "${mbedtls_file}-apache.tgz" "${mbedtls_url}"
        tar -xzf "${mbedtls_file}"-apache.tgz
        cd "${mbedtls_file}" || exit
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "${Error} ${mbedtls_file} 安装失败！"
            exit 1
        fi
    else
        echo -e "${Info} ${mbedtls_file} 已经安装！"
    fi
}

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。" && exit 1
}

check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
}

#开启系统 TCP Fast Open
enable_systfo() {
	sysctl="/etc/sysctl.conf"
	str="net.ipv4.tcp_fastopen=3"
	value=$(grep -c "$str" $sysctl)
	kernel=$(uname -r | awk -F . '{print $1}')
	if [ "$kernel" -ge 3 ]; then
		echo 3 >/proc/sys/net/ipv4/tcp_fastopen
		if [[ $value -ne 1 ]]; then
			echo "$str" >> $sysctl && sysctl -p >/dev/null 2>&1
		fi
		[[ ! -e $Local ]] && echo "fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.d/local.conf && sysctl --system >/dev/null 2>&1
	else
		echo -e "$Error系统内核版本过低，无法支持 TCP Fast Open ！"
	fi
}

check_installed_status(){
	[[ ! -e ${FILE} ]] && echo -e "${Error} Shadowsocks-libev 没有安装，请检查 !" && exit 1
}

check_status(){
	status=`systemctl status shadowsocks-libev | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1`
}

get_latest_version(){
    ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z "${ver}" ] && echo "Shadowsocks-libev 版本获取失败！" && exit 1
    shadowsocks_libev_ver="shadowsocks-libev-$(echo "${ver}" | sed -e 's/^[a-zA-Z]//g')"
    download_link="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${ver}/${shadowsocks_libev_ver}.tar.gz"
}

# check_version(){
#     check_installed "ss-server"
#     if [ $? -eq 0 ]; then
#         installed_ver=$(ss-server -h | grep shadowsocks-libev | cut -d' ' -f2)
#         get_latest_version
#         latest_ver=$(echo "${ver}" | sed -e 's/^[a-zA-Z]//g')
#         if [ "${latest_ver}" == "${installed_ver}" ]; then
#             return 0
#         else
#             return 1
#         fi
#     else
#         return 2
#     fi
# }

check_new_ver(){
	new_ver=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases | jq -r '[.[] | select(.prerelease == false) | select(.draft == false) | .tag_name] | .[0]')
	[[ -z ${new_ver} ]] && echo -e "${Error} Shadowsocks-libev 最新版本获取失败！" && exit 1
	echo -e "${Info} 检测到 Shadowsocks-libev 最新版本为 [ ${new_ver} ]"
}

check_ver_comparison(){
	now_ver=$(cat ${Now_ver_File})
	if [[ "${now_ver}" != "${new_ver}" ]]; then
		echo -e "${Info} 发现 Shadowsocks-libev 已有新版本 [ ${new_ver} ]，旧版本 [ ${now_ver} ]"
		read -e -p "是否更新 ? [Y/n] :" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ $yn == [Yy] ]]; then
			check_status
			[[ "$status" == "running" ]] && systemctl stop shadowsocks-libev
			\cp "${CONF}" "/tmp/config.json"
			rm -rf ${FOLDER}
			Pre_install
			mv "/tmp/config.json" "${CONF}"
			Start
		fi
	else
		echo -e "${Info} 当前 Shadowsocks-libev 已是最新版本 [ ${new_ver} ]" && exit 1
	fi
}

Pre_install(){
	if [[ ! -e "${FOLDER}" ]]; then
		mkdir "${FOLDER}"
	else
		[[ -e "${FILE}" ]] && rm -rf "${FILE}"
	fi
	echo -e "${Info} 开始编译安装 Shadowsocks-libev……"
    install_libsodium
    install_mbedtls
    ldconfig
	wget --no-check-certificate -cq -t3 -T60 -O "${shadowsocks_libev_ver}.tar.gz" "${download_link}"
    tar -xzf "${shadowsocks_libev_ver}".tar.gz
    cd "${shadowsocks_libev_ver}" || exit
    ./configure --disable-documentation
    make && make install
    echo "${new_ver}" > ${Now_ver_File}
    echo -e "${Info} Shadowsocks-libev 主程序编译安装完毕！"
    cd /root || exit
    rm -rf "${shadowsocks_libev_ver}" "${shadowsocks_libev_ver}".tar.gz
    rm -rf ${libsodium_file} ${libsodium_file}.tar.gz
    rm -rf "${mbedtls_file}" "${mbedtls_file}"-apache.tgz
}

Service(){
	echo '
[Unit]
Description= Shadowsocks libev Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service
[Service]
LimitNOFILE=32767 
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStartPre=/bin/sh -c 'ulimit -n 51200'
ExecStart=/usr/local/bin/ss-server -c /etc/shadowsocks-libev/config.json
[Install]
WantedBy=multi-user.target' > /etc/systemd/system/shadowsocks-libev.service
systemctl enable --now shadowsocks-libev
	echo -e "${Info} Shadowsocks-libev 服务配置完成 !"
}

Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		yum update && yum install epel-release -y && yum install gettext gcc autoconf libtool automake make asciidoc xmlto c-ares-devel libev-devel jq git unzip python2 c-ares-devel rng-tools -y
	else
		apt-get update && apt-get install --no-install-recommends gettext build-essential autoconf libtool libpcre3-dev asciidoc xmlto libev-dev libc-ares-dev automake libmbedtls-dev libsodium-dev jq git unzip python2 libc-ares2 libc-ares-dev libev-dev rng-tools -y
	fi
	HRNGDEVICE=/dev/urandom
	rngd -r /dev/urandom
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}

Write_config(){
	cat > ${CONF}<<-EOF
{
    "server": ["0.0.0.0", "::1"],
    "server_port": ${port},
    "password": "${password}",
    "method": "${cipher}",
    "fast_open": ${tfo},
    "mode": "tcp_and_udp",
    "user": "nobody",
    "timeout": 300,
    "nameserver": "8.8.8.8"
}
EOF
}

Read_config(){
	[[ ! -e ${CONF} ]] && echo -e "${Error} Shadowsocks-libev 配置文件不存在 !" && exit 1
	port=$(cat ${CONF}|jq -r '.server_port')
	password=$(cat ${CONF}|jq -r '.password')
	cipher=$(cat ${CONF}|jq -r '.method')
	tfo=$(cat ${CONF}|jq -r '.fast_open')
}

Set_port(){
	while true
		do
		echo -e "${Tip} 本步骤不涉及系统防火墙端口操作，请手动放行相应端口！"
		echo -e "请输入 Shadowsocks-libev 端口 [1-65535]"
		read -e -p "(默认: 2525):" port
		[[ -z "${port}" ]] && port="2525"
		echo $((${port}+0)) &>/dev/null
		if [[ $? -eq 0 ]]; then
			if [[ ${port} -ge 1 ]] && [[ ${port} -le 65535 ]]; then
				echo && echo "=================================="
				echo -e "	端口 : ${Red_background_prefix} ${port} ${Font_color_suffix}"
				echo "==================================" && echo
				break
			else
				echo "输入错误, 请输入正确的端口。"
			fi
		else
			echo "输入错误, 请输入正确的端口。"
		fi
		done
}

Set_tfo(){
	echo -e "是否开启 TCP Fast Open ？
==================================
${Green_font_prefix} 1.${Font_color_suffix} 开启  ${Green_font_prefix} 2.${Font_color_suffix} 关闭
=================================="
	read -e -p "(默认：1.开启)：" tfo
	[[ -z "${tfo}" ]] && tfo="1"
	if [[ ${tfo} == "1" ]]; then
		tfo=true
		enable_systfo
	else
		tfo=false
	fi
	echo && echo "=================================="
	echo -e "TCP Fast Open 开启状态：${Red_background_prefix} ${tfo} ${Font_color_suffix}"
	echo "==================================" && echo
}

Set_password(){
	echo "请输入 Shadowsocks-libev 密码 [0-9][a-z][A-Z]"
	read -e -p "(默认: 随机生成):" password
	[[ -z "${password}" ]] && password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
	echo && echo "=================================="
	echo -e "	密码 : ${Red_background_prefix} ${password} ${Font_color_suffix}"
	echo "==================================" && echo
}

Set_cipher(){
	echo -e "请选择 Shadowsocks-libev 加密方式
==================================	
 ${Green_font_prefix} 1.${Font_color_suffix} chacha20-ietf-poly1305 ${Green_font_prefix}(推荐)${Font_color_suffix}
 ${Green_font_prefix} 2.${Font_color_suffix} aes-128-gcm ${Green_font_prefix}(推荐)${Font_color_suffix}
 ${Green_font_prefix} 3.${Font_color_suffix} aes-256-gcm ${Green_font_prefix}(推荐)${Font_color_suffix}
 ${Green_font_prefix} 4.${Font_color_suffix} plain ${Red_font_prefix}(不推荐)${Font_color_suffix}
 ${Green_font_prefix} 5.${Font_color_suffix} none ${Red_font_prefix}(不推荐)${Font_color_suffix}
 ${Green_font_prefix} 6.${Font_color_suffix} table
 ${Green_font_prefix} 7.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 8.${Font_color_suffix} aes-256-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-256-ctr 
 ${Green_font_prefix}10.${Font_color_suffix} camellia-256-cfb
 ${Green_font_prefix}11.${Font_color_suffix} rc4-md5
 ${Green_font_prefix}12.${Font_color_suffix} chacha20-ietf
==================================
 ${Tip} 如需其它加密方式请手动修改配置文件 !" && echo
	read -e -p "(默认: 1. chacha20-ietf-poly1305):" cipher
	[[ -z "${cipher}" ]] && cipher="1"
	if [[ ${cipher} == "1" ]]; then
		cipher="chacha20-ietf-poly1305"
	elif [[ ${cipher} == "2" ]]; then
		cipher="aes-128-gcm"
	elif [[ ${cipher} == "3" ]]; then
		cipher="aes-256-gcm"
	elif [[ ${cipher} == "4" ]]; then
		cipher="plain"
	elif [[ ${cipher} == "5" ]]; then
		cipher="none"
	elif [[ ${cipher} == "6" ]]; then
		cipher="table"
	elif [[ ${cipher} == "7" ]]; then
		cipher="aes-128-cfb"
	elif [[ ${cipher} == "8" ]]; then
		cipher="aes-256-cfb"
	elif [[ ${cipher} == "9" ]]; then
		cipher="aes-256-ctr"
	elif [[ ${cipher} == "10" ]]; then
		cipher="camellia-256-cfb"
	elif [[ ${cipher} == "11" ]]; then
		cipher="arc4-md5"
	elif [[ ${cipher} == "12" ]]; then
		cipher="chacha20-ietf"
	else
		cipher="chacha20-ietf-poly1305"
	fi
	echo && echo "=================================="
	echo -e "	加密 : ${Red_background_prefix} ${cipher} ${Font_color_suffix}"
	echo "==================================" && echo
}

Set(){
	check_installed_status
	echo && echo -e "你要做什么？
——————————————————————————————————
 ${Green_font_prefix}1.${Font_color_suffix}  修改 端口配置
 ${Green_font_prefix}2.${Font_color_suffix}  修改 密码配置
 ${Green_font_prefix}3.${Font_color_suffix}  修改 加密配置
 ${Green_font_prefix}4.${Font_color_suffix}  修改 TFO 配置
——————————————————————————————————
 ${Green_font_prefix}5.${Font_color_suffix}  修改 全部配置" && echo
	read -e -p "(默认: 取消):" modify
	[[ -z "${modify}" ]] && echo "已取消..." && exit 1
	if [[ "${modify}" == "1" ]]; then
		Read_config
		Set_port
		password=${password}
		cipher=${cipher}
		tfo=${tfo}
		Write_config
		Restart
	elif [[ "${modify}" == "2" ]]; then
		Read_config
		Set_password
		port=${port}
		cipher=${cipher}
		tfo=${tfo}
		Write_config
		Restart
	elif [[ "${modify}" == "3" ]]; then
		Read_config
		Set_cipher
		port=${port}
		password=${password}
		tfo=${tfo}
		Write_config
		Restart
	elif [[ "${modify}" == "4" ]]; then
		Read_config
		Set_tfo
		cipher=${cipher}
		port=${port}
		password=${password}
		Write_config
		Restart
	elif [[ "${modify}" == "5" ]]; then
		Read_config
		Set_port
		Set_password
		Set_cipher
		Set_tfo
		Write_config
		Restart
	else
		echo -e "${Error} 请输入正确的数字(1-5)" && exit 1
	fi
}

Install(){
	[[ -e ${FILE} ]] && echo -e "${Error} 检测到 Shadowsocks-libev 已安装 !" && exit 1
	echo -e "${Info} 开始设置 配置..."
	Set_port
	Set_password
	Set_cipher
	Set_tfo
	echo -e "${Info} 开始安装/配置 依赖..."
	Installation_dependency
	echo -e "${Info} 开始下载/安装..."
	check_new_ver
	Pre_install
	echo -e "${Info} 开始安装系统服务脚本..."
	Service
	echo -e "${Info} 开始写入 配置文件..."
	Write_config
	echo -e "${Info} 所有步骤 安装完毕，开始启动..."
	Start
}

Uninstall(){
    clear
    printf "确认要卸载 Shadowsocks-libev 么？ (y/n)"
    printf "\n"
    read -e -p "(默认：n):" answer
    [ -z "${answer}" ] && answer="n"

    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ps -ef | grep -v grep | grep -i "ss-server" > /dev/null 2>&1
        systemctl stop shadowsocks-libev
        systemctl disable shadowsocks-libev
        rm -fr /etc/shadowsocks-libev
        rm -f /usr/local/bin/ss-local
        rm -f /usr/local/bin/ss-tunnel
        rm -f /usr/local/bin/ss-server
        rm -f /usr/local/bin/ss-manager
        rm -f /usr/local/bin/ss-redir
        rm -f /usr/local/bin/ss-nat
        rm -f /usr/local/lib/libshadowsocks-libev.a
        rm -f /usr/local/lib/libshadowsocks-libev.la
        rm -f /usr/local/include/shadowsocks.h
        rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
        rm -f /usr/local/share/man/man1/ss-local.1
        rm -f /usr/local/share/man/man1/ss-tunnel.1
        rm -f /usr/local/share/man/man1/ss-server.1
        rm -f /usr/local/share/man/man1/ss-manager.1
        rm -f /usr/local/share/man/man1/ss-redir.1
        rm -f /usr/local/share/man/man1/ss-nat.1
        rm -f /usr/local/share/man/man8/shadowsocks-libev.8
        rm -fr /usr/local/share/doc/shadowsocks-libev
        echo "Shadowsocks-libev 卸载成功！"
    else
        echo
        echo "卸载操作已取消！"
        echo
    fi
    sleep 3s
    Start_Menu
}

Start(){
	check_installed_status
	check_status
	[[ "$status" == "running" ]] && echo -e "${Info} Shadowsocks-libev 已在运行 !" && exit 1
	systemctl start shadowsocks-libev
	check_status
	[[ "$status" == "running" ]] && echo -e "${Info} Shadowsocks-libev 启动成功 !"
    sleep 3s
    Start_Menu
}

Stop(){
	check_installed_status
	check_status
	[[ !"$status" == "running"} ]] && echo -e "${Error} Shadowsocks-libev 没有运行，请检查 !" && exit 1
	systemctl stop shadowsocks-libev
    sleep 3s
    Start_Menu
}

Restart(){
	check_installed_status
	systemctl restart shadowsocks-libev
	echo -e "${Info} Shadowsocks-libev 重启完毕!"
	sleep 3s
	View
    Start_Menu
}

Update(){
	check_installed_status
	check_new_ver
	check_ver_comparison
	echo -e "${Info} Shadowsocks-libev 更新完毕 !"
    sleep 3s
    Start_Menu
}

getipv4(){
	ipv4=$(wget -qO- -4 -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ipv4}" ]]; then
		ipv4=$(wget -qO- -4 -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ipv4}" ]]; then
			ipv4=$(wget -qO- -4 -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ipv4}" ]]; then
				ipv4="IPv4_Error"
			fi
		fi
	fi
}
getipv6(){
	ipv6=$(wget -qO- -6 -t1 -T2 ifconfig.co)
	if [[ -z "${ipv6}" ]]; then
		ipv6="IPv6_Error"
	fi
}

urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}

Link_QR(){
	if [[ "${ipv4}" != "IPv4_Error" ]]; then
		SSbase64=$(urlsafe_base64 "${cipher}:${password}@${ipv4}:${port}")
		SSurl="ss://${SSbase64}"
		SSQRcode="https://cli.im/api/qrcode/code?text=${SSurl}"
		link_ipv4=" 链接  [IPv4] : ${Red_font_prefix}${SSurl}${Font_color_suffix} \n 二维码[IPv4] : ${Red_font_prefix}${SSQRcode}${Font_color_suffix}"
	fi
	if [[ "${ipv6}" != "IPv6_Error" ]]; then
		SSbase64=$(urlsafe_base64 "${cipher}:${password}@${ipv6}:${port}")
		SSurl="ss://${SSbase64}"
		SSQRcode="https://cli.im/api/qrcode/code?text=${SSurl}"
		link_ipv6=" 链接  [IPv6] : ${Red_font_prefix}${SSurl}${Font_color_suffix} \n 二维码[IPv6] : ${Red_font_prefix}${SSQRcode}${Font_color_suffix}"
	fi
}

View(){
	check_installed_status
	Read_config
	getipv4
	getipv6
	Link_QR
	clear && echo
	echo -e "Shadowsocks-libev 配置："
	echo -e "——————————————————————————————————"
	[[ "${ipv4}" != "IPv4_Error" ]] && echo -e " 地址\t: ${Green_font_prefix}${ipv4}${Font_color_suffix}"
	[[ "${ipv6}" != "IPv6_Error" ]] && echo -e " 地址\t: ${Green_font_prefix}${ipv6}${Font_color_suffix}"
	echo -e " 端口\t: ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " 密码\t: ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " 加密\t: ${Green_font_prefix}${cipher}${Font_color_suffix}"
	echo -e " TFO\t: ${Green_font_prefix}${tfo}${Font_color_suffix}"
	[[ ! -z "${link_ipv4}" ]] && echo -e "${link_ipv4}"
	[[ ! -z "${link_ipv6}" ]] && echo -e "${link_ipv6}"
	echo -e "——————————————————————————————————"
	Before_Start_Menu
}

Status(){
	echo -e "${Info} 获取 Shadowsocks-libev 活动日志 ……"
	echo -e "${Tip} 返回主菜单请按 q ！"
	systemctl status shadowsocks-libev
	# Start_Menu
}

Update_Shell(){
	echo -e "当前版本为 [ ${sh_ver} ]，开始检测最新版本..."
	sh_new_ver=$(wget --no-check-certificate -qO- "https://raw.githubusercontent.com/xOS/Shadowsocks-libev/master/shadowsocks-libev.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} 检测最新版本失败 !" && Start_Menu
	if [[ ${sh_new_ver} != ${sh_ver} ]]; then
		echo -e "发现新版本[ ${sh_new_ver} ]，是否更新？[Y/n]"
		read -p "(默认: y):" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ ${yn} == [Yy] ]]; then
			wget -O ss-libev.sh --no-check-certificate https://raw.githubusercontent.com/xOS/Shadowsocks-libev/master/shadowsocks-libev.sh && chmod +x ss-libev.sh
			echo -e "脚本已更新为最新版本[ ${sh_new_ver} ] !"
			echo -e "3s后执行新脚本"
            sleep 3s
            bash ss-libev.sh
		else
			echo && echo "	已取消..." && echo
            sleep 3s
            Start_Menu
		fi
	else
		echo -e "当前已是最新版本[ ${sh_new_ver} ] !"
		sleep 3s
        Start_Menu
	fi
	sleep 3s
    	bash ss-libev.sh
}

Before_Start_Menu() {
    echo && echo -n -e "${yellow}* 按回车返回主菜单 *${plain}" && read temp
    Start_Menu
}

Start_Menu(){
clear
check_root
check_sys
get_latest_version
action=$1
	echo && echo -e "  
==================================
Shadowsocks-libev 管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
==================================
 ${Green_font_prefix} 0.${Font_color_suffix} 更新脚本
——————————————————————————————————
 ${Green_font_prefix} 1.${Font_color_suffix} 安装 Shadowsocks-libev
 ${Green_font_prefix} 2.${Font_color_suffix} 更新 Shadowsocks-libev
 ${Green_font_prefix} 3.${Font_color_suffix} 卸载 Shadowsocks-libev
——————————————————————————————————
 ${Green_font_prefix} 4.${Font_color_suffix} 启动 Shadowsocks-libev
 ${Green_font_prefix} 5.${Font_color_suffix} 停止 Shadowsocks-libev
 ${Green_font_prefix} 6.${Font_color_suffix} 重启 Shadowsocks-libev
——————————————————————————————————
 ${Green_font_prefix} 7.${Font_color_suffix} 设置 配置信息
 ${Green_font_prefix} 8.${Font_color_suffix} 查看 配置信息
 ${Green_font_prefix} 9.${Font_color_suffix} 查看 运行状态
——————————————————————————————————
 ${Green_font_prefix} 10.${Font_color_suffix} 退出脚本
==================================" && echo
	if [[ -e ${FILE} ]]; then
		check_status
		if [[ "$status" == "running" ]]; then
			echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} 并 ${Green_font_prefix}已启动${Font_color_suffix}"
		else
			echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} 但 ${Red_font_prefix}未启动${Font_color_suffix}"
		fi
	else
		echo -e " 当前状态: ${Red_font_prefix}未安装${Font_color_suffix}"
	fi
	echo
	read -e -p " 请输入数字 [0-10]:" num
	case "$num" in
		0)
		Update_Shell
		;;
		1)
		Install
		;;
		2)
		Update
		;;
		3)
		Uninstall
		;;
		4)
		Start
		;;
		5)
		Stop
		;;
		6)
		Restart
		;;
		7)
		Set
		;;
		8)
		View
		;;
		9)
		Status
		;;
		10)
		exit 1
		;;
		*)
		echo "请输入正确数字 [0-10]"
		;;
	esac
}
Start_Menu
