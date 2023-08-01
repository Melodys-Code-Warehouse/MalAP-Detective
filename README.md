# Malicious Access Point Detective (MalAP Detective)

## 1 Collaborators 

Sort in the alphabetic order:

- @[ChaoHanley](https://github.com/ChaoHanley)
- @SuiseiKawaii
- @YuanHansen2233
- @melody0123
- @vivalayan

## 2 Overview

This is a tool for end users to detect malicious access point on their own machines.

## 3 Functions

### 3.1 ARP Spoofing Detection

Since in ARP spoofing the attacker needs to send ARP packets to the gateway and then to the victim machine, we in fact update the ARP cache with the gateway's IP address corresponding to the attacker's mac address. An obvious way to detect this is to send an ARP packet to the gateway several times to get the gateway's mac address, and compare it with the mac address in the previous packet, if it is not the same, it means that it has suffered an ARP spoofing attack.

## 4 Result
![Alt text](<L7%{YN]{GPS08INLB5)~RW6-1.png>)