#!/bin/bash
cd /usr/bin
GITHUB=raw.githubusercontent.com/dugong-lewat/autoscript2/main
echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Main Menu${NC}"
wget -q -O menu "https://${GITHUB}/menu/menu.sh"
wget -q -O vmess "https://${GITHUB}/menu/vmess.sh"
wget -q -O vless "https://${GITHUB}/menu/vless.sh"
wget -q -O trojan "https://${GITHUB}/menu/trojan.sh"
wget -q -O shadowsocks "https://${GITHUB}/menu/shadowsocks.sh"
wget -q -O ss2022 "https://${GITHUB}/menu/ss2022.sh"
wget -q -O allxray "https://${GITHUB}/menu/allxray.sh"
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Vmess${NC}"
wget -q -O add-vmess "https://${GITHUB}/vmess/add-vmess.sh"
wget -q -O del-vmess "https://${GITHUB}/vmess/del-vmess.sh"
wget -q -O extend-vmess "https://${GITHUB}/vmess/extend-vmess.sh"
wget -q -O trialvmess "https://${GITHUB}/vmess/trialvmess.sh"
wget -q -O cek-vmess "https://${GITHUB}/vmess/cek-vmess.sh"
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Vless${NC}"
wget -q -O add-vless "https://${GITHUB}/vless/add-vless.sh"
wget -q -O del-vless "https://${GITHUB}/vless/del-vless.sh"
wget -q -O extend-vless "https://${GITHUB}/vless/extend-vless.sh"
wget -q -O trialvless "https://${GITHUB}/vless/trialvless.sh"
wget -q -O cek-vless "https://${GITHUB}/vless/cek-vless.sh"
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Trojan${NC}"
wget -q -O add-trojan "https://${GITHUB}/trojan/add-trojan.sh"
wget -q -O del-trojan "https://${GITHUB}/trojan/del-trojan.sh"
wget -q -O extend-trojan "https://${GITHUB}/trojan/extend-trojan.sh"
wget -q -O trialtrojan "https://${GITHUB}/trojan/trialtrojan.sh"
wget -q -O cek-trojan "https://${GITHUB}/trojan/cek-trojan.sh"
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Shadowsocks${NC}"
wget -q -O add-ss "https://${GITHUB}/ss/add-ss.sh"
wget -q -O del-ss "https://${GITHUB}/ss/del-ss.sh"
wget -q -O extend-ss "https://${GITHUB}/ss/extend-ss.sh"
wget -q -O trialss "https://${GITHUB}/ss/trialss.sh"
wget -q -O cek-ss "https://${GITHUB}/ss/cek-ss.sh"
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Shadowsocks 2022${NC}"
wget -q -O add-ss2022 "https://${GITHUB}/ss2022/add-ss2022.sh"
wget -q -O del-ss2022 "https://${GITHUB}/ss2022/del-ss2022.sh"
wget -q -O extend-ss2022 "https://${GITHUB}/ss2022/extend-ss2022.sh"
wget -q -O trialss2022 "https://${GITHUB}/ss2022/trialss2022.sh"
wget -q -O cek-ss2022 "https://${GITHUB}/ss2022/cek-ss2022.sh"
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu All Xray${NC}"
wget -q -O add-xray "https://${GITHUB}/allxray/add-xray.sh"
wget -q -O del-xray "https://${GITHUB}/allxray/del-xray.sh"
wget -q -O extend-xray "https://${GITHUB}/allxray/extend-xray.sh"
wget -q -O trialxray "https://${GITHUB}/allxray/trialxray.sh"
wget -q -O cek-xray "https://${GITHUB}/allxray/cek-xray.sh"
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Log${NC}"
wget -q -O log-create "https://${GITHUB}/log/log-create.sh"
wget -q -O log-vmess "https://${GITHUB}/log/log-vmess.sh"
wget -q -O log-vless "https://${GITHUB}/log/log-vless.sh"
wget -q -O log-trojan "https://${GITHUB}/log/log-trojan.sh"
wget -q -O log-ss "https://${GITHUB}/log/log-ss.sh"
wget -q -O log-ss2022 "https://${GITHUB}/log/log-ss2022.sh"
wget -q -O log-allxray "https://${GITHUB}/log/log-allxray.sh"
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Other Menu${NC}"
wget -q -O xp "https://${GITHUB}/other/xp.sh"
wget -q -O dns "https://${GITHUB}/other/dns.sh"
wget -q -O certxray "https://${GITHUB}/other/certxray.sh"
wget -q -O about "https://${GITHUB}/other/about.sh"
wget -q -O clear-log "https://${GITHUB}/other/clear-log.sh"
wget -q -O changer "https://${GITHUB}/other/changer.sh"
echo -e "${GB}[ INFO ]${NC} ${YB}Download All Menu Done${NC}"
sleep 2
chmod +x add-vmess
chmod +x del-vmess
chmod +x extend-vmess
chmod +x trialvmess
chmod +x cek-vmess

chmod +x add-vless
chmod +x del-vless
chmod +x extend-vless
chmod +x trialvless
chmod +x cek-vless

chmod +x add-trojan
chmod +x del-trojan
chmod +x extend-trojan
chmod +x trialtrojan
chmod +x cek-trojan

chmod +x add-ss
chmod +x del-ss
chmod +x extend-ss
chmod +x trialss
chmod +x cek-ss

chmod +x add-ss2022
chmod +x del-ss2022
chmod +x extend-ss2022
chmod +x trialss2022
chmod +x cek-ss2022

chmod +x add-xray
chmod +x del-xray
chmod +x extend-xray
chmod +x trialxray
chmod +x cek-xray

chmod +x log-create
chmod +x log-vmess
chmod +x log-vless
chmod +x log-trojan
chmod +x log-ss
chmod +x log-ss2022
chmod +x log-allxray

chmod +x menu
chmod +x vmess
chmod +x vless
chmod +x trojan
chmod +x shadowsocks
chmod +x ss2022
chmod +x allxray

chmod +x xp
chmod +x dns
chmod +x certxray
chmod +x about
chmod +x clear-log
chmod +x changer
cd
