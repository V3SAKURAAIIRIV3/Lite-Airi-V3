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
function addssh(){
clear
domen=`cat /etc/xray/domain`
portsshws=`cat ~/log-install.txt | grep -w "Websocket SSH(HTTP)" | cut -d: -f2 | awk '{print $1}'`
wsssl=`cat /root/log-install.txt | grep -w "Websocket SSL(HTTPS)" | cut -d: -f2 | awk '{print $1}'`

echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}                SSH PANEL MENU               ${NC}" | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
read -p "   Username      : " Login

CEKFILE=/etc/xray/ssh.txt
if [ -f "$CEKFILE" ]; then
file001="OK"
else
touch /etc/xray/ssh.txt
fi

if grep -qw "$Login" /etc/xray/ssh.txt; then
echo -e "   [Error] Username \e[31m$Login\e[0m already exist"
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-ssh
else
echo "$Login" >> /etc/xray/ssh.txt
fi

if [ -z $Login ]; then
echo -e "   [Error] Username cannot be empty "
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo ""
read -n 1 -s -r -p "    Press any key to back on menu"
menu-ssh
fi

read -p "   Password      : " Pass
if [ -z $Pass ]; then
echo -e "   [Error] Password cannot be empty "
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
fi
read -p "   Expired (hari): " masaaktif
if [ -z $masaaktif ]; then
echo -e "   [Error] EXP Date cannot be empty "
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-ssh
fi

IP=$(curl -sS ifconfig.me);
ossl=`cat /root/log-install.txt | grep -w "OpenVPN" | cut -f2 -d: | awk '{print $6}'`
opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
ssl="$(cat ~/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
sqd="$(cat ~/log-install.txt | grep -w "Squid Proxy" | cut -d: -f2)"
ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"

wsovpn=`cat /root/log-install.txt | grep -w "Websocket OpenVPN" | cut -d: -f2 | awk '{print $1}'`
OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
ODBear=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`

sleep 1
clear
useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
PID=`ps -ef |grep -v grep | grep sshws |awk '{print $2}'`

if [[ ! -z "${PID}" ]]; then
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}                SSH PANEL MENU               ${NC}" | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "Username     : $Login" 
echo -e "Password     : $Pass"
echo -e "Expired On   : $exp" 
echo -e "IP           : $IP"  | tee -a /etc/log-create-user.log
echo -e "Host         : $domen"  | tee -a /etc/log-create-user.log
echo -e "OpenSSH      : $opensh" | tee -a /etc/log-create-user.log
echo -e "OpenVPN      : TCP 1194, UDP 2200, SSL 442" | tee -a /etc/log-create-user.log
echo -e "Dropbear     : $db"  | tee -a /etc/log-create-user.log
echo -e "SSH-WS       : $portsshws"  | tee -a /etc/log-create-user.log
echo -e "SSH-SSL-WS   : $wsssl"  | tee -a /etc/log-create-user.log
echo -e "SSL/TLS      :$ssl"  | tee -a /etc/log-create-user.log
echo -e "WS OpenVPN   : $wsovpn" | tee -a /etc/log-create-user.log
echo -e "OHP OpenSSH  : $OhpSSH" | tee -a /etc/log-create-user.log
echo -e "OHP Dbear    : $ODBear" | tee -a /etc/log-create-user.log
echo -e "Port OVPN OHP: 8000"
echo -e "Squid        :$sqd" | tee -a /etc/log-create-user.log
echo -e "UDPGW        : 7100-7300"  | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "OpenVPN TCP  : $ovpn http://$MYIP:81/client-tcp-$ovpn.ovpn"
echo -e "OpenVPN UDP  : $ovpn2 http://$MYIP:81/client-udp-$ovpn2.ovpn"
echo -e "OpenVPN SSL  : 442 http://$MYIP:81/client-tcp-ssl.ovpn"
echo -e "OpenVPN OHP  : OHP 8000 http://${MYIP}:81/client-tcp-ohp.ovpn"
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "PAYLOAD WS 1 : CF-RAY http://bug.com HTTP/1.1[crlf]Host: $domen [crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "PAYLOAD WS 2 : GET / HTTP/1.1[crlf]Host: $domen[crlf]Upgrade: websocket[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "PAYLOAD WS 3 : GET wss://bug.com/ HTTP/1.1[crlf]Host: $domen[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
else
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}                SSH PANEL MENU               ${NC}" | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "Username     : $Login" 
echo -e "Password     : $Pass"
echo -e "Expired On   : $exp" 
echo -e "IP           : $IP"  | tee -a /etc/log-create-user.log
echo -e "Host         : $domen"  | tee -a /etc/log-create-user.log
echo -e "OpenSSH      : $opensh" | tee -a /etc/log-create-user.log
echo -e "OpenVPN      : TCP 1194, UDP 2200, SSL 442" | tee -a /etc/log-create-user.log
echo -e "Dropbear     : $db"  | tee -a /etc/log-create-user.log
echo -e "SSH-WS       : $portsshws"  | tee -a /etc/log-create-user.log
echo -e "SSH-SSL-WS   : $wsssl"  | tee -a /etc/log-create-user.log
echo -e "SSL/TLS      :$ssl"  | tee -a /etc/log-create-user.log
echo -e "WS OpenVPN   : $wsovpn" | tee -a /etc/log-create-user.log
echo -e "OHP OpenSSH  : $OhpSSH" | tee -a /etc/log-create-user.log
echo -e "OHP Dbear    : $ODBear" | tee -a /etc/log-create-user.log
echo -e "Port OVPN OHP: 8000"
echo -e "Squid        :$sqd" | tee -a /etc/log-create-user.log
echo -e "UDPGW        : 7100-7300"  | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "OpenVPN TCP  : $ovpn http://$MYIP:81/client-tcp-$ovpn.ovpn"
echo -e "OpenVPN UDP  : $ovpn2 http://$MYIP:81/client-udp-$ovpn2.ovpn"
echo -e "OpenVPN SSL  : 442 http://$MYIP:81/client-tcp-ssl.ovpn"
echo -e "OpenVPN OHP  : OHP 8000 http://${MYIP}:81/client-tcp-ohp.ovpn"
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "PAYLOAD WS 1 : CF-RAY http://bug.com HTTP/1.1[crlf]Host: $domen [crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "PAYLOAD WS 2 : GET / HTTP/1.1[crlf]Host: $domen[crlf]Upgrade: websocket[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "PAYLOAD WS 3 : GET wss://bug.com/ HTTP/1.1[crlf]Host: $domen[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
fi
echo -e ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-ssh
}
function sshwss(){
    clear
portdb=`cat ~/log-install.txt | grep -w "Dropbear" | cut -d: -f2|sed 's/ //g' | cut -f2 -d","`
portsshws=`cat ~/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
if [ -f "/etc/systemd/system/sshws.service" ]; then
clear
else
wget -q -O /usr/bin/proxy3.js "https://raw.githubusercontent.com/V3SAKURAAIIRIV3/Lite-Airi-V3/main/ssh/proxy3.js"
cat <<EOF > /etc/systemd/system/sshws.service
[Unit]
Description=WSenabler
Documentation=https://SSHSEDANG.MY.ID

[Service]
Type=simple
ExecStart=/usr/bin/ssh-wsenabler
KillMode=process
Restart=on-failure
RestartSec=1s

[Install]
WantedBy=multi-user.target
EOF

fi

function start() {
        clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}                WEBSOCKET MENU               "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
wget -q -O /usr/bin/ssh-wsenabler "https://raw.githubusercontent.com/V3SAKURAAIIRIV3/Lite-Airi-V3/main/ssh/sshws-true.sh" && chmod +x /usr/bin/ssh-wsenabler
systemctl daemon-reload >/dev/null 2>&1
systemctl enable sshws.service >/dev/null 2>&1
systemctl start sshws.service >/dev/null 2>&1
sed -i "/SSH Websocket/c\   - SSH Websocket           : $portsshws [ON]" /root/log-install.txt
echo -e "   [ ${green}INFO${NC} ] • ${green}SSH Websocket Started${NC}"
echo -e "   [ ${green}INFO${NC} ] • Restart is require for Changes"
echo -e "            to take effect"
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e ""
read -n 1 -s -r -p "  Press any key to back on menu"
sshwss 
}

function stop() {
        clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}                WEBSOCKET MENU               "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
systemctl stop sshws.service >/dev/null 2>&1
tmux kill-session -t sshws >/dev/null 2>&1
sed -i "/SSH Websocket/c\   - SSH Websocket           : $portsshws [OFF]" /root/log-install.txt
echo -e "   [ ${green}INFO${NC} ] • ${red}SSH Websocket Stopped${NC}"
echo -e "   [ ${green}INFO${NC} ] • Restart is require for Changes"
echo -e "            to take effect"
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e ""
read -n 1 -s -r -p "  Press any key to back on menu"
sshwss 
}

clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}                WEBSOCKET MENU               "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
PID=`ps -ef |grep -v grep | grep sshws |awk '{print $2}'`
if [[ ! -z "${PID}" ]]; then
echo -e "     Websocket Is ${green}Running${NC}"
else
echo -e "     Websocket Is ${red}Not Running${NC}"
fi
echo -e " "
echo -e "   ${GREEN}[ ${PURPLE}01 ${GREEN}] ${yellow}ON SSHWS"
echo -e "   ${GREEN}[ ${PURPLE}02 ${GREEN}] ${yellow}OFF SSHWS"
echo -e " " 
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "      ${GREEN}[ ${red}00 ${GREEN}] ${yellow}BACK TO MENU                    "
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e ""
echo -e   " ${yellow}Press x or [ Ctrl+C ] • To-Exit"
echo ""
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo ""
echo -ne " Select menu : "; read opt
case $opt in
01 | 1) clear ; start ;;
02 | 2) clear ; stop ;;
00 | 0) clear ; menu-ssh ;;
*) clear ; menu-set ;;
esac
}
function cekssh(){

clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}               SSH ACTIVE USERS              "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e ""

if [ -e "/var/log/auth.log" ]; then
        LOG="/var/log/auth.log";
fi
if [ -e "/var/log/secure" ]; then
        LOG="/var/log/secure";
fi
               
data=( `ps aux | grep -i dropbear | awk '{print $2}'`);
cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" > /tmp/login-db.txt;
for PID in "${data[@]}"
do
        cat /tmp/login-db.txt | grep "dropbear\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $10}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $12}'`;
        if [ $NUM -eq 1 ]; then
                echo "$PID - $USER - $IP";
        fi

done
echo " "
cat $LOG | grep -i sshd | grep -i "Accepted password for" > /tmp/login-db.txt
data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`);

for PID in "${data[@]}"
do
        cat /tmp/login-db.txt | grep "sshd\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $9}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $11}'`;
        if [ $NUM -eq 1 ]; then
                echo "$PID - $USER - $IP";
        fi


done
if [ -f "/etc/openvpn/server/openvpn-tcp.log" ]; then
        echo " "

        cat /etc/openvpn/server/openvpn-tcp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' > /tmp/vpn-login-tcp.txt
        cat /tmp/vpn-login-tcp.txt
fi

if [ -f "/etc/openvpn/server/openvpn-udp.log" ]; then
        echo " "

        cat /etc/openvpn/server/openvpn-udp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' > /tmp/vpn-login-udp.txt
        cat /tmp/vpn-login-udp.txt
fi


rm -f /tmp/login-db-pid.txt
rm -f /tmp/login-db.txt
rm -f /tmp/vpn-login-tcp.txt
rm -f /tmp/vpn-login-udp.txt
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo "";
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
}

function delssh(){
clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}               SSH DELETE USERS              "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
read -p "   Username : " Pengguna

if [ -z $Pengguna ]; then
echo -e "   [Error] Username cannot be empty "
else
if getent passwd $Pengguna > /dev/null 2>&1; then
userdel $Pengguna > /dev/null 2>&1
sed -i "s/$Pengguna//g" /etc/xray/ssh.txt
echo -e "   [ ${green}INFO${NC} ] User $Pengguna was removed."
else
echo -e "   [ ${green}INFO${NC} ] Failure: User $Pengguna Not Exist."
fi
fi
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
}

function renewssh(){
clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}              RENEW SSH ACCOUNT              "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
read -p "   Username : " User

if getent passwd $User > /dev/null 2>&1; then
ok="ok"
else
echo -e "   [ ${green}INFO${NC} ] Failure: User $User Not Exist."
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu
fi

if [ -z $User ]; then
echo -e "   [Error] Username cannot be empty "
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu
fi

egrep "^$User" /etc/passwd >/dev/null
if [ $? -eq 0 ]; then
read -p "   Day Extend : " Days
if [ -z $Days ]; then
Days="1"
fi
Today=`date +%s`
Days_Detailed=$(( $Days * 86400 ))
Expire_On=$(($Today + $Days_Detailed))
Expiration=$(date -u --date="1970-01-01 $Expire_On sec GMT" +%Y/%m/%d)
Expiration_Display=$(date -u --date="1970-01-01 $Expire_On sec GMT" '+%d %b %Y')
passwd -u $User
usermod -e  $Expiration $User
egrep "^$User" /etc/passwd >/dev/null
echo -e "$Pass\n$Pass\n"|passwd $User &> /dev/null
clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}              RENEW SSH ACCOUNT              "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "   Username   : $User"
echo -e "   Days Added : $Days Days"
echo -e "   Expires on : $Expiration_Display"
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
else
clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}              RENEW SSH ACCOUNT              "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "   Username Doesnt Exist      "
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
fi
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
}


function memberssh(){
clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}              RENEW SSH ACCOUNT              "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}"     
echo " USERNAME          EXP DATE         STATUS"
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
while read expired
do
AKUN="$(echo $expired | cut -d: -f1)"
ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
exp="$(chage -l $AKUN | grep "Account expires" | awk -F": " '{print $2}')"
status="$(passwd -S $AKUN | awk '{print $2}' )"
if [[ $ID -ge 1000 ]]; then
if [[ "$status" = "L" ]]; then
printf "%-17s %2s %-17s %2s \n" " • $AKUN" "$exp     " "LOCK"
else
printf "%-17s %2s %-17s %2s \n" " • $AKUN" "$exp     " "UNLOCK"
fi
fi
done < /etc/passwd
JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo "   Total: $JUMLAH User"
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
}

function trialssh(){
clear
domen=`cat /etc/xray/domain`
portsshws=`cat ~/log-install.txt | grep -w "Websocket SSH(HTTP)" | cut -d: -f2 | awk '{print $1}'`
wsssl=`cat /root/log-install.txt | grep -w "Websocket SSL(HTTPS)" | cut -d: -f2 | awk '{print $1}'`

clear

IP=$(curl -sS ifconfig.me);
ossl=`cat /root/log-install.txt | grep -w "OpenVPN" | cut -f2 -d: | awk '{print $6}'`
opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
ssl="$(cat ~/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
sqd="$(cat ~/log-install.txt | grep -w "Squid Proxy" | cut -d: -f2)"
ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"

wsovpn=`cat /root/log-install.txt | grep -w "Websocket OpenVPN" | cut -d: -f2 | awk '{print $1}'`
OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
ODBear=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`

Login=LiteAiriV3-`</dev/urandom tr -dc X-Z0-9 | head -c4`
hari="1"
Pass=1
echo Ping Host &> /dev/null
echo Create Akun: $Login &> /dev/null
sleep 0.5
echo Setting Password: $Pass &> /dev/null
sleep 0.5
clear
useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
PID=`ps -ef |grep -v grep | grep sshws |awk '{print $2}'`

if [[ ! -z "${PID}" ]]; then
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}              SSH TRIAL ACCOUNT              "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "Username     : $Login" 
echo -e "Password     : $Pass"
echo -e "Expired On   : $exp" 
echo -e "IP           : $IP"  | tee -a /etc/log-create-user.log
echo -e "Host         : $domen"  | tee -a /etc/log-create-user.log
echo -e "OpenSSH      : $opensh" | tee -a /etc/log-create-user.log
echo -e "OpenVPN      : TCP 1194, UDP 2200, SSL 442" | tee -a /etc/log-create-user.log
echo -e "Dropbear     : $db"  | tee -a /etc/log-create-user.log
echo -e "SSH-WS       : $portsshws"  | tee -a /etc/log-create-user.log
echo -e "SSH-SSL-WS   : $wsssl"  | tee -a /etc/log-create-user.log
echo -e "SSL/TLS      :$ssl"  | tee -a /etc/log-create-user.log
echo -e "WS OpenVPN   : $wsovpn" | tee -a /etc/log-create-user.log
echo -e "OHP OpenSSH  : $OhpSSH" | tee -a /etc/log-create-user.log
echo -e "OHP Dbear    : $ODBear" | tee -a /etc/log-create-user.log
echo -e "Port OVPN OHP: 8000"
echo -e "Squid        :$sqd" | tee -a /etc/log-create-user.log
echo -e "UDPGW        : 7100-7300"  | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "OpenVPN TCP  : $ovpn http://$MYIP:81/client-tcp-$ovpn.ovpn"
echo -e "OpenVPN UDP  : $ovpn2 http://$MYIP:81/client-udp-$ovpn2.ovpn"
echo -e "OpenVPN SSL  : 442 http://$MYIP:81/client-tcp-ssl.ovpn"
echo -e "OpenVPN OHP  : OHP 8000 http://${MYIP}:81/client-tcp-ohp.ovpn"
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "PAYLOAD WS 1 : CF-RAY http://bug.com HTTP/1.1[crlf]Host: $domen [crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "PAYLOAD WS 2 : GET / HTTP/1.1[crlf]Host: $domen[crlf]Upgrade: websocket[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "PAYLOAD WS 3 : GET wss://bug.com/ HTTP/1.1[crlf]Host: $domen[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 

else

echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}              SSH TRIAL ACCOUNT              "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "Username     : $Login" 
echo -e "Password     : $Pass"
echo -e "Expired On   : $exp" 
echo -e "IP           : $IP"  | tee -a /etc/log-create-user.log
echo -e "Host         : $domen"  | tee -a /etc/log-create-user.log
echo -e "OpenSSH      : $opensh" | tee -a /etc/log-create-user.log
echo -e "OpenVPN      : TCP 1194, UDP 2200, SSL 442" | tee -a /etc/log-create-user.log
echo -e "Dropbear     : $db"  | tee -a /etc/log-create-user.log
echo -e "SSH-WS       : $portsshws"  | tee -a /etc/log-create-user.log
echo -e "SSH-SSL-WS   : $wsssl"  | tee -a /etc/log-create-user.log
echo -e "SSL/TLS      :$ssl"  | tee -a /etc/log-create-user.log
echo -e "WS OpenVPN   : $wsovpn" | tee -a /etc/log-create-user.log
echo -e "OHP OpenSSH  : $OhpSSH" | tee -a /etc/log-create-user.log
echo -e "OHP Dbear    : $ODBear" | tee -a /etc/log-create-user.log
echo -e "Port OVPN OHP: 8000"
echo -e "Squid        :$sqd" | tee -a /etc/log-create-user.log
echo -e "UDPGW        : 7100-7300"  | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "OpenVPN TCP  : $ovpn http://$MYIP:81/client-tcp-$ovpn.ovpn"
echo -e "OpenVPN UDP  : $ovpn2 http://$MYIP:81/client-udp-$ovpn2.ovpn"
echo -e "OpenVPN SSL  : 442 http://$MYIP:81/client-tcp-ssl.ovpn"
echo -e "OpenVPN OHP  : OHP 8000 http://${MYIP}:81/client-tcp-ohp.ovpn"
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e "PAYLOAD WS 1 : CF-RAY http://bug.com HTTP/1.1[crlf]Host: $domen [crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "PAYLOAD WS 2 : GET / HTTP/1.1[crlf]Host: $domen[crlf]Upgrade: websocket[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "PAYLOAD WS 3 : GET wss://bug.com/ HTTP/1.1[crlf]Host: $domen[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]" | tee -a /etc/log-create-user.log
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
fi
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
}
clear
echo -e "${CYAN}═════════════════════════════════════════════${NC}" 
echo -e "${bred1}                MENU SSH/OVPN                "${NC}
echo -e "${CYAN}═════════════════════════════════════════════${NC}"
echo -e " " 
echo -e "   ${GREEN}[ ${PURPLE}01 ${GREEN}] ${yellow}CREATE ACCOUNT SSH/OVPN"
echo -e "   ${GREEN}[ ${PURPLE}02 ${GREEN}] ${yellow}TRIAL ACCOUNT SSH/OVPN"
echo -e "   ${GREEN}[ ${PURPLE}03 ${GREEN}] ${yellow}USER ONLINE ACCOUNT SSH/OVPN"
echo -e "   ${GREEN}[ ${PURPLE}04 ${GREEN}] ${yellow}ENABLE WS ACCOUNT SSH/OVPN"
echo -e "   ${GREEN}[ ${PURPLE}05 ${GREEN}] ${yellow}DELETE ACCOUNT SSH/OVPN"
echo -e "   ${GREEN}[ ${PURPLE}06 ${GREEN}] ${yellow}RENEW ACCOUNT SSH/OVPN"
echo -e "   ${GREEN}[ ${PURPLE}07 ${GREEN}] ${yellow}USER LIST ACCOUNT SSH/OVPN"
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
01 | 1) clear ; addssh ;;
02 | 2) clear ; trialssh ;;
03 | 3) clear ; cekssh ;;
04 | 4) clear ; sshwss ;;
05 | 5) clear ; delssh ;;
06 | 6) clear ; renewssh ;;
07 | 7) clear ; memberssh ;;
00 | 0) clear ; menu ;;
*) clear ; menu-ssh ;;
esac