#!/bin/bash
# // font color configuration
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
Font="\033[0m"
gray="\e[1;30m"
total_ram=$(grep "MemTotal: " /proc/meminfo | awk '{ print $2}')
totalram=$(($total_ram / 1024))
MYIP=$(curl -sS ipv4.icanhazip.com)
LAST_DOMAIN="$(cat /var/lib/dnsvps.conf)"
red() { echo -e "\\033[32;1m${*}\\033[0m"; }
clear

function get_acme_domain() {
    baru=$(cat /var/lib/dnsvps.conf)
    clear
    echo -e " ┌─────────────────────────────────────────────────────────┐"
    echo -e "─│                        ${CYAN}WELCOME TO${NC}                       │─"
    echo -e "─│    ${ORANGE}┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┌─┐┬─┐┌─┐┌┬┐┬┬ ┬┌┬┐${NC}    │─"
    echo -e "─│    ${ORANGE}├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   ├─┘├┬┘├┤ │││││ ││││${NC}    │─"
    echo -e "─│    ${ORANGE}┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴  ┴└─└─┘┴ ┴┴└─┘┴ ┴${NC}    │─"
    echo -e "─│        ${RED}ANGGUN_TUNNEL${NC} | ${GREEN}TELEGRAM: @amantubilah${NC}       │─"
    echo -e " └─────────────────────────────────────────────────────────┘"
    echo -e "─────────────────────────────────────────────────────────────"
    echo -e "               ${GREEN}PROSES GANTI DOMAIN ${NC}"
    echo -e "─────────────────────────────────────────────────────────────"
    echo -e "   [${ORANGE}INFO${NC}] ${CYAN}Proses sedang berlangsung${NC} "
    systemctl stop nginx
	systemctl stop xray
    sleep 2
    echo -e "   [${ORANGE}INFO${NC}] ${CYAN}Memperbarui semua sertifikat${NC}"
    sleep 2
    echo -e "   [${ORANGE}INFO${NC}] ${CYAN}proses config sertifikat server${NC}"
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
    /root/.acme.sh/acme.sh --issue -d $baru --standalone -k ec-256 >/dev/null 2>&1
    ~/.acme.sh/acme.sh --installcert -d $baru --fullchainpath /usr/local/etc/xray/fullchain.crt --keypath /usr/local/etc/xray/private.key  --ecc >/dev/null 2>&1
    cat /usr/local/etc/xray/fullchain.crt /usr/local/etc/xray/private.key | tee >/dev/null 2>&1
    echo -e "   [${GREEN}DONE${NC}] ${CYAN}Pembaruan Sertifikat Selesai${NC}"
    sed -i "s/${LAST_DOMAIN}/${baru}/g" /etc/nginx/conf.d/xray.conf >/dev/null 2>&1
    sed -i "s/${LAST_DOMAIN}/${baru}/g" /var/www/html/index.html >/dev/null 2>&1
    sed -i "s/${LAST_DOMAIN}/${baru}/g" /var/www/html/index.html/trojan >/dev/null 2>&1
	sed -i "s/${LAST_DOMAIN}/${baru}/g" /var/www/html/index.html/vmess >/dev/null 2>&1
	sed -i "s/${LAST_DOMAIN}/${baru}/g" /var/www/html/index.html/vless >/dev/null 2>&1
	sed -i "s/${LAST_DOMAIN}/${baru}/g" /var/www/html/index.html/ss >/dev/null 2>&1
	sed -i "s/${LAST_DOMAIN}/${baru}/g" /var/www/html/index.html/ss2022 >/dev/null 2>&1
	sed -i "s/${LAST_DOMAIN}/${baru}/g" /var/www/html/index.html/allxray >/dev/null 2>&1
    sleep 2
    echo -e "   [${ORANGE}INFO${NC}] ${CYAN}Restart Daemon Reload Service${NC}"
    systemctl daemon-reload >/dev/null 2>&1
    sleep 2
    echo -e "   [${ORANGE}INFO${NC}] ${CYAN}Restart Nginx WebServer${NC}"
    systemctl restart nginx >/dev/null 2>&1
    sleep 2
    echo -e "   [${ORANGE}INFO${NC}] ${CYAN}Restart Xray Service${NC}"
    systemctl restart xray >/dev/null 2>&1
    sleep 2
    echo -e "   [${GREEN}DONE${NC}] ${CYAN}Ganti Domain dan Restart Service Selesai"
    sleep 2
}

function renew_domain() {
    read -rp "Input ur Domain/Host : " -e domain
	rm -rf /usr/local/etc/xray/domain
	rm -rf /var/lib/dnsvps.conf
    echo $domain >/var/lib/dnsvps.conf
	echo "$baru" > /usr/local/etc/xray/domain
    get_acme_domain
}

cf() {
    echo -e "   [${ORANGE}INFO${NC}] ${CYAN}ponting ke vpnpro.tech proses${NC} "
    wget https://raw.githubusercontent.com/arismaramar/sldns/main/cfdvpnpro.sh >/dev/null 2>&1 && chmod +x cfdvpnpro.sh && ./cfdvpnpro.sh >/dev/null 2>&1
    get_acme_domain
}
cf2() {
    echo -e "   [${ORANGE}INFO${NC}] ${CYAN}ponting ke anggunre.shop proses${NC} "
    wget https://raw.githubusercontent.com/arismaramar/sldns/main/cfdanggunre.sh >/dev/null 2>&1 && chmod +x cfdanggunre.sh && ./cfdanggunre.sh >/dev/null 2>&1
    get_acme_domain
}

clear
echo -e " ┌─────────────────────────────────────────────────────────┐"
echo -e "─│                        ${CYAN}WELCOME TO${NC}                       │─"
echo -e "─│    ${ORANGE}┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┌─┐┬─┐┌─┐┌┬┐┬┬ ┬┌┬┐${NC}    │─"
echo -e "─│    ${ORANGE}├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   ├─┘├┬┘├┤ │││││ ││││${NC}    │─"
echo -e "─│    ${ORANGE}┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴  ┴└─└─┘┴ ┴┴└─┘┴ ┴${NC}    │─"
echo -e "─│        ${RED}anggun_tunnel${NC} | ${GREEN}TELEGRAM: @amantubilahn${NC}       │─"
echo -e " └─────────────────────────────────────────────────────────┘"
echo -e "─────────────────────────────────────────────────────────────
              ${CYAN}Hostname${NC}     :  ${ORANGE}$LAST_DOMAIN${NC}
              ${CYAN}Public IP${NC}    :  ${ORANGE}$MYIP${NC}
              ${CYAN}Total RAM${NC}    :  ${ORANGE}$totalram MB${NC}
─────────────────────────────────────────────────────────────"
echo -e "  ${CYAN}[1]${NC} ${RED}•${NC} Gunakan Domain Sendiri/pribadi"
echo -e "  ${CYAN}[2]${NC} ${RED}•${NC} Gunakan Domain vpnpro.tech"
echo -e "  ${CYAN}[3]${NC} ${RED}•${NC} Gunakan Domain anggunre.shop"
echo -e "  ${CYAN}[0]${NC} ${RED}•${NC} Kembali Ke Menu"
echo -e "─────────────────────────────────────────────────────────────"
read -p "Silahkan masukkan pilihan anda [1-2] : " NUM_MENU

case $NUM_MENU in
1)
    renew_domain
    ;;
2)
    cf
    ;;
	
3)
    cf2
    ;;
	
0)
    menu
    ;;
esac
