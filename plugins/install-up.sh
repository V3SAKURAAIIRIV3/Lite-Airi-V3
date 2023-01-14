#!/bin/bash
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
yl='\e[32;1m'
bl='\e[36;1m'
gl='\e[32;1m'
rd='\e[31;1m'
mg='\e[0;95m'
blu='\e[34m'
op='\e[35m'
or='\033[1;33m'
bd='\e[1m'
color1='\e[031;1m'
color2='\e[34;1m'
color3='\e[0m'
red='\e[1;31m'
bred1='\e[0;47;30m'
bred='\e[41m'
blue='\e[0;34m'
blue_b='\e[1;94m'
yellow='\e[1;33m'
purple='\e[1;35m'
white='\e[1;37m'
try='\e[0;103m'
cyan='\e[1;36m'
green='\e[1;32m'
NC='\e[0m'

dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
###########- COLOR CODE -##############
colornow=$(cat /etc/sakurav3/theme/color.conf)
export NC="\e[0m"
export YELLOW='\033[0;33m';
export RED="\033[0;31m" 
export COLOR1="$(cat /etc/sakurav3/theme/$colornow | grep -w "TEXT" | cut -d: -f2|sed 's/ //g')"
export COLBG1="$(cat /etc/sakurav3/theme/$colornow | grep -w "BG" | cut -d: -f2|sed 's/ //g')"                    
###########- END COLOR CODE -##########

echo -e "   [ ${green}INFO${NC} ] Remove Old Script"


sleep 2
echo -e "   [ ${green}INFO${NC} ] Downloading New Script"

sleep 2
echo -e "   [ ${green}INFO${NC} ] Download Changelog File"
wget -q -O /root/changelog.txt "https://raw.githubusercontent.com/V3SAKURAAIIRIV3/Lite-Airi-V3/main/plugins/changelog.txt" && chmod +x /root/changelog.txt
echo -e "   [ ${green}INFO${NC} ] Read Changelog? ./root/changelog.txt"
mv /usr/local/bin/xray /usr/local/bin/xray.bak && wget -q -O /usr/local/bin/xray "https://github.com/dharak36/Xray-core/releases/download/v1.0.0/xray.linux.64bit" && chmod 755 /usr/local/bin/xray && restart
sleep 2
