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
NC="\e[0m"
RED="\033[0;31m" 
 
WH='\033[1;37m'                  
###########- END COLOR CODE -##########

BURIQ () {
    curl -sS https://raw.githubusercontent.com/V3SAKURAAIRIV3/permission/main/access > /root/tmp
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
    for user in "${data[@]}"
    do
    exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
    d1=(`date -d "$exp" +%s`)
    d2=(`date -d "$biji" +%s`)
    exp2=$(( (d1 - d2) / 86400 ))
    if [[ "$exp2" -le "0" ]]; then
    echo $user > /etc/.$user.ini
    else
    rm -f /etc/.$user.ini > /dev/null 2>&1
    fi
    done
    rm -f /root/tmp
}

MYIP=$(curl -sS ipv4.icanhazip.com)
Name=$(curl -sS https://raw.githubusercontent.com/V3SAKURAAIRIV3/permission/main/access | grep $MYIP | awk '{print $2}')
echo $Name > /usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman () {
if [ -f "/etc/.$Name.ini" ]; then
CekTwo=$(cat /etc/.$Name.ini)
    if [ "$CekOne" = "$CekTwo" ]; then
        res="Expired"
    fi
else
res="Permission Accepted..."
fi
}

PERMISSION () {
    MYIP=$(curl -sS ipv4.icanhazip.com)
    IZIN=$(curl -sS https://raw.githubusercontent.com/V3SAKURAAIRIV3/permission/main/access | awk '{print $4}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
    Bloman
    else
    res="Permission Denied!"
    fi
    BURIQ
}
red='\e[1;31m'
green='\e[1;32m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
PERMISSION
if [ -f /home/needupdate ]; then
red "Your script need to update first !"
exit 0
elif [ "$res" = "Permission Accepted..." ]; then
echo -ne
else
red "Permission Denied!"
exit 0
fi
function status(){
clear
cek=$(service ssh status | grep active | cut -d ' ' -f5)
if [ "$cek" = "active" ]; then
stat=-f5
else
stat=-f7
fi
cekray=`cat /root/log-install.txt | grep -ow "XRAY" | sort | uniq`
if [ "$cekray" = "XRAY" ]; then
rekk='xray'
becek='XRAY'
else
rekk='v2ray'
becek='V2RAY'
fi

ssh=$(service ssh status | grep active | cut -d ' ' $stat)
if [ "$ssh" = "active" ]; then
ressh="${GREEN}Running${NC}"
else
ressh="${RED}Not Running${NC}"
fi
sshstunel=$(service stunnel4 status | grep active | cut -d ' ' $stat)
if [ "$sshstunel" = "active" ]; then
resst="${GREEN}Running${NC}"
else
resst="${RED}Not Running${NC}"
fi
sshws=$(service ws-dropbear status | grep active | cut -d ' ' $stat)
if [ "$sshws" = "active" ]; then
rews="${GREEN}Running${NC}"
else
rews="${RED}Not Running${NC}"
fi

sshws2=$(service ws-stunnel status | grep active | cut -d ' ' $stat)
if [ "$sshws2" = "active" ]; then
rews2="${GREEN}Running${NC}"
else
rews2="${RED}Not Running${NC}"
fi

db=$(service dropbear status | grep active | cut -d ' ' $stat)
if [ "$db" = "active" ]; then
resdb="${GREEN}Running${NC}"
else
resdb="${RED}Not Running${NC}"
fi
 
v2r=$(service $rekk status | grep active | cut -d ' ' $stat)
if [ "$v2r" = "active" ]; then
resv2r="${GREEN}Running${NC}"
else
resv2r="${RED}Not Running${NC}"
fi
vles=$(service $rekk status | grep active | cut -d ' ' $stat)
if [ "$vles" = "active" ]; then
resvles="${GREEN}Running${NC}"
else
resvles="${RED}Not Running${NC}"
fi
trj=$(service $rekk status | grep active | cut -d ' ' $stat)
if [ "$trj" = "active" ]; then
restr="${GREEN}Running${NC}"
else
restr="${RED}Not Running${NC}"
fi

tcp="$(systemctl show --now openvpn-server@server-tcp-1194 --no-page)"
status1=$(echo "${tcp}" | grep 'ActiveState=' | cut -f2 -d=)
if [ "${status1}" = "active" ]; then
ovpntcp="${GREEN}Running${NC}"
else
ovpntcp="${RED}Not Running${NC}"
fi

udp="$(systemctl show --now openvpn-server@server-udp-2200 --no-page)"
status2=$(echo "${udp}" | grep 'ActiveState=' | cut -f2 -d=)
if [ "${status2}" = "active" ]; then
ovpnudp="${GREEN}Running${NC}"
else
ovpnudp="${RED}Not Running${NC}"
fi

#status="$(systemctl show dropbear-ohp.service --no-page)"                                   
#status_text=$(echo "${status}" | grep 'ActiveState=' | cut -f2 -d=)                     
#if [ "${status_text}" == "active" ]                                                     
#then                                                                                    
#echo -e " DROPBEAR OHP       : "$green"Online"$NC""                  
#else                                                                                    
#echo -e " DROPBEAR OHP       : "$red"Not Online (Error)"$NC""        
#fi

#status="$(systemctl show openvpn-ohp.service --no-page)"                                   
#status_text=$(echo "${status}" | grep 'ActiveState=' | cut -f2 -d=)                     
#if [ "${status_text}" == "active" ]                                                     
#then                                                                                    
#echo -e " OPENVPN OHP        : "$green"Online"$NC""                  
#else                                                                                    
#echo -e " OPENVPN OHP        : "$red"Not Online (Error)"$NC""        
#fi


#ovhp="$(systemctl show ohp.service --no-page)"
#status3=$(echo "${ovhp}" | grep 'ActiveState=' | cut -f2 -d=)
#if [ "${status3}" = "active" ]; then
#ohp="${GREEN}Running${NC}"
#else
#ohp="${RED}Not Running${NC}"
#fi



ningx=$(service nginx status | grep active | cut -d ' ' $stat)
if [ "$ningx" = "active" ]; then
resnx="${GREEN}Running${NC}"
else
resnx="${RED}Not Running${NC}"
fi

squid=$(service squid status | grep active | cut -d ' ' $stat)
if [ "$squid" = "active" ]; then
ressq="${GREEN}Running${NC}"
else
ressq="${RED}Not Running${NC}"
fi
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "${bred1}                SERVER RUNNING               "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "  ${yellow}SSH                         : $ressh"
echo -e "  ${yellow}OVPN TCP                    : $ovpntcp"
echo -e "  ${yellow}OVPN UDP                    : $ovpnudp"
echo -e "  ${yellow}OVPN OHP                    : $ovpntcp"
echo -e "  ${yellow}SQUID                       : $ressq"
echo -e "  ${yellow}DROPBEAR                    : $resdb"
echo -e "  ${yellow}NGINX                       : $resnx"
echo -e "  ${yellow}WS DROPBEAR                 : $rews"
echo -e "  ${yellow}WS STUNNEL                  : $rews2"
echo -e "  ${yellow}STUNNEL                     : $resst"
echo -e "  ${yellow}XRAY VMESS                  : $resv2r"
echo -e "  ${yellow}XRAY VLESS                  : $resvles"
echo -e "  ${yellow}XRAY TROJAN                 : $restr"
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-set
}
function restart(){
clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "${bred1}                SERVER RUNNING               "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
systemctl daemon-reload
echo -e "    [ ${green}INFO${NC} ] • Starting ...                        "
sleep 1
systemctl restart ssh
echo -e "    [ ${green}INFO${NC} ] • Restarting SSH Services             "
sleep 1
systemctl restart squid
echo -e "    [ ${green}INFO${NC} ] • Restarting Squid Services           "
sleep 1
systemctl restart openvpn
systemctl restart --now openvpn-server@server-tcp-1194
systemctl restart --now openvpn-server@server-udp-2200
echo -e "    [ ${green}INFO${NC} ] • Restarting OpenVPN Services         "
sleep 1
systemctl restart nginx
echo -e "    [ ${green}INFO${NC} ] • Restarting Nginx Services           "
sleep 1
systemctl restart dropbear
echo -e "    [ ${green}INFO${NC} ] • Restarting Dropbear Services        "
sleep 1
systemctl restart ws-dropbear
echo -e "    [ ${green}INFO${NC} ] • Restarting Ws-Dropbear Services     "
sleep 1
systemctl restart ws-stunnel
echo -e "    [ ${green}INFO${NC} ] • Restarting Ws-Stunnel Services      "
sleep 1
systemctl restart stunnel4
echo -e "    [ ${green}INFO${NC} ] • Restarting Stunnel4 Services        "
sleep 1
systemctl restart xray
echo -e "    [ ${green}INFO${NC} ] • Restarting Xray Services            "
sleep 1
systemctl restart cron
echo -e "    [ ${green}INFO${NC} ] • Restarting Cron Services            "
echo -e "    [ ${green}INFO${NC} ] • All Services Restates Successfully  "
sleep 1
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-set
}

[[ -f /etc/ontorrent ]] && sts="\033[0;32m[ON] \033[0m" || sts="\033[1;31m[OFF]\033[0m"

enabletorrent() {
[[ ! -f /etc/ontorrent ]] && {
sudo iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
sudo iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
sudo iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
sudo iptables-save > /etc/iptables.up.rules
sudo iptables-restore -t < /etc/iptables.up.rules
sudo netfilter-persistent save >/dev/null 2>&1  
sudo netfilter-persistent reload >/dev/null 2>&1 
touch /etc/ontorrent
menu-set
} || {
sudo iptables -D FORWARD -m string --string "get_peers" --algo bm -j DROP
sudo iptables -D FORWARD -m string --string "announce_peer" --algo bm -j DROP
sudo iptables -D FORWARD -m string --string "find_node" --algo bm -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "BitTorrent" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "peer_id=" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string ".torrent" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "torrent" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "announce" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "info_hash" -j DROP
sudo iptables-save > /etc/iptables.up.rules
sudo iptables-restore -t < /etc/iptables.up.rules
sudo netfilter-persistent save >/dev/null 2>&1
sudo netfilter-persistent reload >/dev/null 2>&1 
rm -f /etc/ontorrent
menu-set
}
}

clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "${bred1}                 VPS SETTING                 "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e " " 
echo -e "   ${GREEN}[ ${PURPLE}01 ${GREEN}] ${yellow}RUNNING"
echo -e "   ${GREEN}[ ${PURPLE}02 ${GREEN}] ${yellow}SET BANNER"
echo -e "   ${GREEN}[ ${PURPLE}03 ${GREEN}] ${yellow}BANDWITH USAGE"
echo -e "   ${GREEN}[ ${PURPLE}04 ${GREEN}] ${yellow}ANTI TORRENT${NC} $sts"
echo -e "   ${GREEN}[ ${PURPLE}05 ${GREEN}] ${yellow}TCP TWEAK"
echo -e "   ${GREEN}[ ${PURPLE}06 ${GREEN}] ${yellow}RESTART ALL"
echo -e "   ${GREEN}[ ${PURPLE}07 ${GREEN}] ${yellow}AUTO REBOOT"
echo -e "   ${GREEN}[ ${PURPLE}08 ${GREEN}] ${yellow}SPEEDTEST"
echo -e " " 
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "      ${GREEN}[ ${red}00 ${GREEN}] ${yellow}BACK TO MENU                    "
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e ""
echo -e   " ${yellow}Press x or [ Ctrl+C ] • To-Exit"
echo ""
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e ""
echo -ne " Select menu : "; read opt
case $opt in
01 | 1) clear ; status ;;
02 | 2) clear ; nano /etc/issue.net ;;
03 | 3) clear ; mbandwith ;;
04 | 4) clear ; enabletorrent ;;
05 | 5) clear ; menu-tcp ;;
06 | 6) clear ; restart ;;
07 | 7) clear ; autoboot ;;
08 | 8) clear ; mspeed ;;
00 | 0) clear ; menu ;;
*) clear ; menu-set ;;
esac