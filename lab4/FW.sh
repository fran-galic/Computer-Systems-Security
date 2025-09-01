#!/bin/sh

FW=/sbin/iptables
DMZ=192.0.2.
LAN=192.168.0.
INET=198.51.100.0/24
DB=${LAN}10
WWW=${DMZ}10
DNS=${DMZ}20
ADM=${LAN}20

# reset i policy
$FW -P INPUT   DROP
$FW -P OUTPUT  DROP
$FW -P FORWARD DROP
$FW -F INPUT; $FW -F OUTPUT; $FW -F FORWARD

# već otvorene / ping
$FW -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$FW -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$FW -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$FW -A INPUT  -p icmp -j ACCEPT
$FW -A OUTPUT -p icmp -j ACCEPT
$FW -A FORWARD -p icmp -j ACCEPT

# hard‑block na početku
$FW -A FORWARD -s $DB -j DROP                 # baza nigdje
$FW -A FORWARD -s $INET -d ${LAN}0/24 -j DROP # internet u LAN

# DMZ uslug
$FW -A FORWARD -p tcp -d $WWW --dport 80  -j ACCEPT
$FW -A FORWARD -p tcp -d $WWW --dport 443 -j ACCEPT
$FW -A FORWARD -p udp -s $DNS --dport 53 -j ACCEPT
$FW -A FORWARD -p tcp -s $DNS --dport 53 -j ACCEPT
$FW -A FORWARD -p tcp -s $ADM -d $WWW --dport 22 -j ACCEPT
$FW -A FORWARD -p tcp -s $ADM -d $DNS --dport 22 -j ACCEPT
$FW -A FORWARD -p tcp -s $WWW -d $DB --dport 10000 -j ACCEPT
$FW -A FORWARD -p udp -s $WWW --dport 53 -j ACCEPT
$FW -A FORWARD -p tcp -s $WWW --dport 53 -j ACCEPT

# LAN dozvole
$FW -A FORWARD -p tcp -s ${LAN}0/24 -d $DB --dport 22    -j ACCEPT
$FW -A FORWARD -p tcp -s ${LAN}0/24 -d $DB --dport 10000 -j ACCEPT
$FW -A FORWARD -p tcp -s ${LAN}0/24 --dport 80 -j ACCEPT
$FW -A FORWARD -p udp -s ${LAN}0/24 --dport 53 -j ACCEPT
$FW -A FORWARD -p tcp -s ${LAN}0/24 --dport 53 -j ACCEPT

# lokalni SSH na FW
$FW -A INPUT -p tcp -s $ADM --dport 22 -j ACCEPT

echo finished
