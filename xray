rm -rf xray
rm -rf install
clear
NC='\e[0m'
DEFBOLD='\e[39;1m'
RB='\e[31;1m'
GB='\e[32;1m'
YB='\e[33;1m'
BB='\e[34;1m'
MB='\e[35;1m'
CB='\e[35;1m'
WB='\e[37;1m'
secs_to_human() {
echo -e "${WB}Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds${NC}"
}
start=$(date +%s)
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt install socat netfilter-persistent -y
apt install vnstat lsof fail2ban -y
apt install curl sudo -y
apt install screen cron screenfetch -y
mkdir /usr/local/ddos
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

mkdir /user >> /dev/null 2>&1
mkdir /tmp >> /dev/null 2>&1
apt install resolvconf network-manager dnsutils bind9 -y
cat > /etc/systemd/resolved.conf << END
[Resolve]
DNS=1.1.1.1 8.8.8.8 
Domains=~.
ReadEtcHosts=yes
END
systemctl enable resolvconf
systemctl enable systemd-resolved
systemctl enable NetworkManager
rm -rf /etc/resolv.conf
rm -rf /etc/resolvconf/resolv.conf.d/head
echo "
nameserver 127.0.0.53
" >> /etc/resolv.conf
echo "
" >> /etc/resolvconf/resolv.conf.d/head
systemctl restart resolvconf
systemctl restart systemd-resolved
systemctl restart NetworkManager
echo "Google DNS" > /user/current
rm /usr/local/etc/xray/city >> /dev/null 2>&1
rm /usr/local/etc/xray/org >> /dev/null 2>&1
rm /usr/local/etc/xray/timezone >> /dev/null 2>&1
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version
 
curl -s ipinfo.io/city >> /usr/local/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /usr/local/etc/xray/org
curl -s ipinfo.io/timezone >> /usr/local/etc/xray/timezone
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
sudo apt-get install speedtest
clear
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
apt install nginx -y
rm /var/www/html/*.html
rm -rf /var/www/html/* >> /dev/null 2>&1
rm /etc/nginx/sites-enabled/default >> /dev/null 2>&1
rm /etc/nginx/sites-available/default >> /dev/null 2>&1
mkdir -p /var/www/html/vmess >> /dev/null 2>&1
mkdir -p /var/www/html/vless >> /dev/null 2>&1
mkdir -p /var/www/html/trojan >> /dev/null 2>&1
mkdir -p /var/www/html/ss >> /dev/null 2>&1
mkdir -p /var/www/html/ss2022 >> /dev/null 2>&1
mkdir -p /var/www/html/allxray >> /dev/null 2>&1
cd /var/www/html/ 
wget https://raw.githubusercontent.com/arismaramar/gif/main/fodder/web.zip
unzip -x web.zip 
chmod 0755  /var/www/html/*
systemctl restart nginx
clear

#DOMAIN
dnsvpnpro() {
wget https://raw.githubusercontent.com/arismaramar/sldns/main/cfdvpnpro.sh && chmod +x cfdvpnpro.sh 
clear
}
dnsanggunre() {
wget https://raw.githubusercontent.com/arismaramar/sldns/main/cfdanggunre.sh && chmod +x cfdanggunre.sh 
clear
}

touch /usr/local/etc/xray/domain
echo -e ""
resdomain() {
clear
apt install jq curl -y
}
fun_bar 'resdomain'
echo -e "${tyblue}┌──────────────────────────────────────────┐${NC}"
echo -e "${tyblue}│ \033[1;37mPlease select a your Choice to Set Domain${tyblue}│${NC}"
echo -e "${tyblue}└──────────────────────────────────────────┘${NC}"
echo -e "${tyblue}┌──────────────────────────────────────────┐${NC}"
echo -e "${tyblue}│  [ 1 ]  \033[1;37mGunakan Domain Sendiri/Private       ${NC}"
echo -e "${tyblue}│  "                                        
echo -e "${tyblue}│  [ 2 ]  \033[1;37mGunakan Domain Dari SC (vpnpro.tech) ${NC}"
echo -e "${tyblue}│     "                                     
echo -e "${tyblue}│  [ 3 ]  \033[1;37mGunakan Domain Dari SC (anggunre.shop)${NC}"
echo -e "${tyblue}│     "                                     
echo -e "${tyblue}└──────────────────────────────────────────┘${NC}"
read -p "   Please select numbers 1-3 or Any Button(Random) : " host
echo ""
if [[ $host == "1" ]]; then
echo -e "   \e[1;32mPlease Enter Your Subdomain $NC"
read -p "   Subdomain: " host1
echo "IP=" >> /var/lib/dnsvps.conf
echo $host1 > /usr/local/etc/xray/domain
echo -e  "${tyblue}┌──────────────────────────────────────────┐${NC}"
echo -e  "${tyblue}│              \033[1;37mTERIMA KASIH                ${tyblue}│${NC}"
echo -e  "${tyblue}│                \033[1;37mANGGUN_TUNNEL                 ${tyblue}│${NC}"
echo -e  "${tyblue}└──────────────────────────────────────────┘${NC}"
echo ""
elif [[ $host == "2" ]]; then
#install cf
fun_bar 'dnsvpnpro'
./cf.sh
echo -e  "${tyblue}┌──────────────────────────────────────────┐${NC}"
echo -e  "${tyblue}│              \033[1;37mTERIMA KASIH                ${tyblue}│${NC}"
echo -e  "${tyblue}│                \033[1;37mANGGUN_TUNNEL                 ${tyblue}│${NC}"
echo -e  "${tyblue}└──────────────────────────────────────────┘${NC}"
echo " "
rm -f /root/cf.sh
clear
#DOMAIN2
elif [[ $host == "3" ]]; then
#install cf
fun_bar 'dnsanggunre'
./cf2.sh
echo -e  "${tyblue}┌──────────────────────────────────────────┐${NC}"
echo -e  "${tyblue}│              \033[1;37mTERIMA KASIH                ${tyblue}│${NC}"
echo -e  "${tyblue}│                \033[1;37mANGGUN_TUNNEL                 ${tyblue}│${NC}"
echo -e  "${tyblue}└──────────────────────────────────────────┘${NC}"
echo " "
rm -f /root/cf2.sh
clear
    fi
clear
systemctl stop nginx
systemctl stop xray
domain=$(cat /usr/local/etc/xray/domain)
curl https://get.acme.sh | sh
source ~/.bashrc
cd .acme.sh
bash acme.sh --issue -d $domain --server letsencrypt --keylength ec-256 --fullchain-file /usr/local/etc/xray/fullchain.crt --key-file /usr/local/etc/xray/private.key --standalone --force
chmod 745 /usr/local/etc/xray/private.key
clear
echo -e "${GB}[ INFO ]${NC} ${YB}Setup Nginx & Xray Conf${NC}"
cipher="aes-128-gcm"
cipher2="2022-blake3-aes-128-gcm"
uuid=$(cat /proc/sys/kernel/random/uuid)
pwtr=$(openssl rand -hex 4)
pwss=$(echo $RANDOM | md5sum | head -c 6; echo;)
userpsk=$(openssl rand -base64 16)
serverpsk=$(openssl rand -base64 16)
echo "$serverpsk" > /usr/local/etc/xray/serverpsk
cat > /usr/local/etc/xray/config.json << END
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "api": {
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ],
    "tag": "api"
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 62789,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
# XTLS
    {
      "listen": "::",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "flow": "xtls-rprx-vision",
            "id": "$uuid"
#vless-xtls
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "alpn": "h2",
            "dest": 2323,
            "xver": 2
          },
          {
            "dest": 800,
            "xver": 2
          },
          {
            "path": "/vless",
            "dest": "@vless-ws",
            "xver": 2
          },
          {
            "path": "/vmess",
            "dest": "@vmess-ws",
            "xver": 2
          },
          {
            "path": "/trojan",
            "dest": "@trojan-ws",
            "xver": 2
          },
          {
            "path": "/ss",
            "dest": "100",
            "xver": 2
          },
          {
            "path": "/ss2022",
            "dest": "110",
            "xver": 2
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "ocspStapling": 3600,
              "certificateFile": "/usr/local/etc/xray/fullchain.crt",
              "keyFile": "/usr/local/etc/xray/private.key"
            }
          ],
          "minVersion": "1.2",
          "cipherSuites": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
          "alpn": [
            "h2",
            "http/1.1"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# TROJAN TCP TLS
    {
      "port": 2323,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$pwtr",
            "level": 0
#trojan-tcp
          }
        ],
        "fallbacks": [
          {
            "dest": "844",
            "xver": 2
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none",
        "tcpSettings": {
          "acceptProxyProtocol": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# VLESS WS
    {
      "listen": "@vless-ws",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "email":"general@vless-ws",
            "id": "$uuid"
#vless

          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/vless"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# VMESS WS
    {
      "listen": "@vmess-ws",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "email": "general@vmess-ws", 
            "id": "$uuid",
            "level": 0
#vmess
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/vmess"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# TROJAN WS
    {
      "listen": "@trojan-ws",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$pwtr",
            "level": 0
#trojan
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/trojan"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# SS WS
    {
      "listen": "127.0.0.1",
      "port": "100",
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
            {
              "method": "aes-128-gcm",
              "password": "$pwss"
#ss
            }
          ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/ss"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# SS2022 WS
    {
      "listen": "127.0.0.1",
      "port": "110",
      "protocol": "shadowsocks",
      "settings": {
        "method": "2022-blake3-aes-128-gcm",
        "password": "$(cat /usr/local/etc/xray/serverpsk)",
        "clients": [
          {
            "password": "$userpsk"
#ss2022
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/ss2022"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# VLESS GRPC
    {
      "listen": "127.0.0.1",
      "port": 11000,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "email":"general@vless-grpc",
            "id": "$uuid"
#vless-grpc

          }
        ],
        "decryption": "none"
      },
      "streamSettings":{
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vless-grpc"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# VMESS GRPC
    {
      "listen": "127.0.0.1",
      "port": 12000,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "email": "general@vmess-grpc", 
            "id": "$uuid",
            "level": 0
#vmess-grpc
          }
        ]
      },
      "streamSettings":{
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "vmess-grpc"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# TROJAN GRPC
    {
      "listen": "127.0.0.1",
      "port": 13000,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$pwtr",
            "level": 0
#trojan-grpc
          }
        ]
      },
      "streamSettings":{
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "trojan-grpc"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# SS GRPC
    {
      "listen": "127.0.0.1",
      "port": 14000,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
            {
              "method": "aes-128-gcm",
              "password": "$pwss"
#ss-grpc
            }
          ],
        "network": "tcp,udp"
      },
      "streamSettings":{
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "ss-grpc"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# SS2022 GRPC
    {
      "listen": "127.0.0.1",
      "port": 15000,
      "protocol": "shadowsocks",
      "settings": {
        "method": "2022-blake3-aes-128-gcm",
        "password": "$(cat /usr/local/etc/xray/serverpsk)",
        "clients": [
          {
            "password": "$userpsk"
#ss2022-grpc
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings":{
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "ss2022-grpc"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
    {
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid"
#universal
          }
        ],
        "fallbacks": [
          {
            "dest": 800,
            "xver": 2
          },
          {
            "dest": 200,
            "xver": 2
          },
          {
            "dest": 210,
            "xver": 2
          },
          {
            "path": "/vless",
            "dest": "@vless-ws",
            "xver": 2
          },
          {
            "path": "/vmess",
            "dest": "@vmess-ws",
            "xver": 2
          },
          {
            "path": "/trojan",
            "dest": "@trojan",
            "xver": 2
          }
        ],
        "decryption": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# TROJAN WS
    {
      "listen": "@trojan",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$pwtr",
            "level": 0
#trojan
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/trojan"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
# SS WS
    {
      "listen": "127.0.0.1",
      "port": "200",
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
            {
              "method": "aes-128-gcm",
              "password": "$pwss"
#ss
            }
          ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/ss"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
    {
      "listen": "127.0.0.1",
      "port": "210",
      "protocol": "shadowsocks",
      "settings": {
        "method": "2022-blake3-aes-128-gcm",
        "password": "$(cat /usr/local/etc/xray/serverpsk)",
        "clients": [
          {
            "password": "$userpsk"
#ss2022
          }
        ],
        "network": "tcp,udp"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "/ss2022"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "default",
      "protocol": "freedom"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    },
    {
      "tag": "DNS-Internal",
      "protocol": "dns",
      "settings": {
        "address": "127.0.0.53",
        "port": 53
      }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "ip": [
          "geoip:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
wget -q -O /etc/nginx/nginx.conf https://raw.githubusercontent.com/arismaramar/autoscript-allxray/main/config/nginx.conf
wget -q -O /etc/nginx/conf.d/xray.conf https://raw.githubusercontent.com/arismaramar/autoscript-allxray/main/config/xray.conf
#sudo sed -i -e 's/127.0.0.1 localhost/${domain}/g' /etc/nginx/conf.d/xray.conf
systemctl restart nginx
systemctl restart xray
echo -e "${GB}[ INFO ]${NC} ${YB}Setup Done${NC}"
sleep 1
clear
# Blokir lalu lintas torrent (BitTorrent)
sudo iptables -A INPUT -p udp --dport 6881:6889 -j DROP
sudo iptables -A INPUT -p tcp --dport 6881:6889 -j DROP
# Blokir lalu lintas torrent dengan modul string
sudo iptables -A INPUT -p tcp --dport 6881:6889 -m string --algo bm --string "BitTorrent" -j DROP
sudo iptables -A INPUT -p udp --dport 6881:6889 -m string --algo bm --string "BitTorrent" -j DROP
# downldo scrip menu
cd /usr/bin
GITHUB="https://raw.githubusercontent.com/autoscript-allxray/main"
echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Main Menu${NC}"
wget -q -O menu ${GITHUB}/menu/menu.sh
wget -q -O vmess ${GITHUB}/menu/vmess.sh
wget -q -O vless ${GITHUB}/menu/vless.sh
wget -q -O trojan ${GITHUB}/menu/trojan.sh
wget -q -O shadowsocks ${GITHUB}/menu/shadowsocks.sh
wget -q -O ss2022 ${GITHUB}/menu/ss2022.sh
wget -q -O allxray ${GITHUB}/menu/allxray.sh
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Vmess${NC}"
wget -q -O add-vmess ${GITHUB}/vmess/add-vmess.sh
wget -q -O del-vmess ${GITHUB}/vmess/del-vmess.sh
wget -q -O extend-vmess ${GITHUB}/vmess/extend-vmess.sh
wget -q -O trialvmess ${GITHUB}/vmess/trialvmess.sh
wget -q -O cek-vmess ${GITHUB}/vmess/cek-vmess.sh
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Vless${NC}"
wget -q -O add-vless ${GITHUB}/vless/add-vless.sh"
wget -q -O del-vless ${GITHUB}/vless/del-vless.sh
wget -q -O extend-vless ${GITHUB}/vless/extend-vless.sh
wget -q -O trialvless ${GITHUB}/vless/trialvless.sh"
wget -q -O cek-vless ${GITHUB}/vless/cek-vless.sh"
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Trojan${NC}"
wget -q -O add-trojan ${GITHUB}/trojan/add-trojan.sh
wget -q -O del-trojan ${GITHUB}/trojan/del-trojan.sh"
wget -q -O extend-trojan ${GITHUB}/trojan/extend-trojan.sh
wget -q -O trialtrojan ${GITHUB}/trojan/trialtrojan.sh
wget -q -O cek-trojan ${GITHUB}/trojan/cek-trojan.sh
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Shadowsocks${NC}"
wget -q -O add-ss ${GITHUB}/ss/add-ss.sh
wget -q -O del-ss ${GITHUB}/ss/del-ss.sh
wget -q -O extend-ss ${GITHUB}/ss/extend-ss.sh
wget -q -O trialss ${GITHUB}/ss/trialss.sh
wget -q -O cek-ss ${GITHUB}/ss/cek-ss.sh
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Shadowsocks 2022${NC}"
wget -q -O add-ss2022 ${GITHUB}/ss2022/add-ss2022.sh
wget -q -O del-ss2022 ${GITHUB}/ss2022/del-ss2022.sh
wget -q -O extend-ss2022 ${GITHUB}/ss2022/extend-ss2022.sh
wget -q -O trialss2022 ${GITHUB}/ss2022/trialss2022.sh
wget -q -O cek-ss2022 ${GITHUB}/ss2022/cek-ss2022.sh
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu All Xray${NC}"
wget -q -O add-xray ${GITHUB}/allxray/add-xray.sh
wget -q -O del-xray ${GITHUB}/allxray/del-xray.sh
wget -q -O extend-xray ${GITHUB}/allxray/extend-xray.sh
wget -q -O trialxray ${GITHUB}/allxray/trialxray.sh
wget -q -O cek-xray ${GITHUB}/allxray/cek-xray.sh
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Menu Log${NC}"
wget -q -O log-create ${GITHUB}/log/log-create.sh
wget -q -O log-vmess ${GITHUB}/log/log-vmess.sh
wget -q -O log-vless ${GITHUB}/log/log-vless.sh
wget -q -O log-trojan ${GITHUB}/log/log-trojan.sh
wget -q -O log-ss ${GITHUB}/log/log-ss.sh
wget -q -O log-ss2022 ${GITHUB}/log/log-ss2022.sh
wget -q -O log-allxray ${GITHUB}/log/log-allxray.sh
sleep 0.5

echo -e "${GB}[ INFO ]${NC} ${YB}Downloading Other Menu${NC}"
wget -q -O xp ${GITHUB}/other/xp.sh
wget -q -O dns ${GITHUB}/other/dns.sh
wget -q -O certxray ${GITHUB}/other/certxray.sh
wget -q -O about ${GITHUB}/other/about.sh
wget -q -O clear-log ${GITHUB}/other/clear-log.sh
wget -q -O changer ${GITHUB}/other/changer.sh
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
echo "0 0 * * * root xp" >> /etc/crontab
echo "*/3 * * * * root clear-log" >> /etc/crontab
systemctl restart cron
cat > /root/.profile << END
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
clear
menu
END
chmod 644 /root/.profile
clear
echo ""
echo -e "${BB}—————————————————————————————————————————————————————————${NC}"
echo -e "                 ${WB}original SCRIPT BY DUGONG revisi anggun${NC}"
echo -e "${BB}—————————————————————————————————————————————————————————${NC}"
echo -e "                 ${WB}»»» Protocol Service «««${NC}  "
echo -e "${BB}—————————————————————————————————————————————————————————${NC}"
echo -e "  ${YB}- Vmess WS CDN TLS${NC}            : ${YB}443${NC}"
echo -e "  ${YB}- Vmess WS CDN${NC}                : ${YB}80${NC}"
echo -e "  ${YB}- Vmess gRPC${NC}                  : ${YB}443${NC}"
echo -e "  ${YB}- Vless XTLS Vision${NC}           : ${YB}443${NC}"
echo -e "  ${YB}- Vless WS CDN TLS${NC}            : ${YB}443${NC}"
echo -e "  ${YB}- Vless WS CDN${NC}                : ${YB}80${NC}"
echo -e "  ${YB}- Vless gRPC${NC}                  : ${YB}443${NC}"
echo -e "  ${YB}- Trojan TCP${NC}                  : ${YB}443${NC}"
echo -e "  ${YB}- Trojan WS CDN TLS${NC}           : ${YB}443${NC}"
echo -e "  ${YB}- Trojan WS CDN${NC}               : ${YB}80${NC}"
echo -e "  ${YB}- Trojan gRPC${NC}                 : ${YB}443${NC}"
echo -e "  ${YB}- Shadowsocks WS CDN TLS${NC}      : ${YB}443${NC}"
echo -e "  ${YB}- Shadowsocks WS CDN${NC}          : ${YB}80${NC}"
echo -e "  ${YB}- Shadowsocks gRPC${NC}            : ${YB}443${NC}"
echo -e "  ${YB}- Shadowsocks 2022 WS CDN TLS${NC} : ${YB}443${NC}"
echo -e "  ${YB}- Shadowsocks 2022 WS CDN${NC}     : ${YB}80${NC}"
echo -e "  ${YB}- Shadowsocks 2022 gRPC${NC}       : ${YB}443${NC}"
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo ""
rm -f xray
secs_to_human "$(($(date +%s) - ${start}))"
echo -e "${YB}[ WARNING ] reboot now ? (Y/N)${NC} "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi
