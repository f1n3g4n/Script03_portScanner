#!/usr/bin/python3
#Script by F1neg4n

import nmap
import os

def welcome():
    welc = 'NMAP Port Scanner'
    info = '[INFO] Python script to scan ports with NMAP'
    os.system('clear')
    print(welc + '\n' + '*' * len(welc))
    print(info)
    print('------------')
    return

def getAddress():
    welcome()
    try:
        ip = input('[+] Enter the IP Address: ')
        while(ip == ''):
            ip = input('[+] Please, enter the IP Address: ')
    except(KeyboardInterrupt):
        os.system('clear')
        welcome()
        print('[-] Interrupted by user!')
        exit()
    return ip

def scannerNmap():
    try:
        host = getAddress()
        print('[+] Scanning open ports ==> ' + host)
        nm = nmap.PortScanner()
        results = nm.scan(host)
        os.system('clear')
        welcome()
        for host in nm.all_hosts():
            print('Host\t: %s' % (host))
            print('State\t: %s' % nm[host].state())
            for proto in nm[host].all_protocols():
                print('Protocol: %s' % proto)
                print('------------')
                lport = nm[host][proto].keys()
                sorted(lport)
                for port in lport:
                    print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
    except(KeyboardInterrupt):
        print('[-] Interrupted by user!')
    return

if __name__ == '__main__':
    scannerNmap()
