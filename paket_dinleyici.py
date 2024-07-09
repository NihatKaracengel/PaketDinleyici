import scapy.all as scapy
from scapy.layers import http
def paket_dinleyici(interface):
    scapy.sniff(iface=interface, store=False, prn=paket_analizi)
def paket_analizi(paket):
    #paket.show()
    if paket.haslayer(http.HTTPRequest):
        if paket.haslayer(scapy.Raw):
            print(paket[scapy.Raw].load)

paket_dinleyici("eth0")