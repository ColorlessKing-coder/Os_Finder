from rich import print
import scapy.all as scapy
import random
import socket
import ast
import time
import os 


class OsFinder:
    def __init__(self,ip_address):
        self.ip = ip_address
    
    
    def __str__(self,ip):
        print(f" OsFinder Attack For {self.ip} ")
        
        
    def __call__(self):
        self.play_police_animation()
        print("[red][ ..+.. ] Detected Operating System With TCP Options...[/red]")
        self.TCP_Option_Analyze(ip_address)
        Enter = input("Give me tcp option Values (İf you have no value please enter q  ): ")
        if Enter == "q":
            print("[red][ ..+.. ] Detected Operating System With Windows Size and TTL Value  ...[/red]")
            self.Os_Detection(ip_address)

            print("[red][ ..+.. ] Detected Operating System With Flag Response  ...[/red]")
            self.flag_response(ip_address)
            
        else:
            options = ast.literal_eval(Enter)# Eval 2 +5 string verisini saki int gibi toplar ve sonucu döndürür x = 2 y = 5   result = eval("x+y")
            print(self.guess_os_from_tcp_options(options))

            print("[red][ ..+.. ] Detected Operating System With Windows Size and TTL Value  ...[/red]")
            finder.Os_Detection(ip_address)

            print("[red][ ..+.. ] Detected Operating System With Flag Response  ...[/red]")
            self.flag_response(ip_address)








    def play_police_animation(self):
        # Renkli ASCII karakterler
        blue = "\033[94m"  # Mavi
        red = "\033[91m"   # Kırmızı
        reset = "\033[0m"  # Renk sıfırlama

        # Animasyon kareleri
        frames = [
            "▓▒░░░░░░░░░░░░░░░░░░░░",
            "▓▓▒░░░░░░░░░░░░░░░░░░░",
            "▓▓▓▒░░░░░░░░░░░░░░░░░░",
            "▓▓▓▓▒░░░░░░░░░░░░░░░░░",
            "▓▓▓▓▓▒░░░░░░░░░░░░░░░░",
            "▓▓▓▓▓▓▒░░░░░░░░░░░░░░░",
            "▓▓▓▓▓▓▓▒░░░░░░░░░░░░░░",
            "▓▓▓▓▓▓▓▓▒░░░░░░░░░░░░░",
            "▓▓▓▓▓▓▓▓▓▒░░░░░░░░░░░░",
            "▓▓▓▓▓▓▓▓▓▓▒░░░░░░░░░░░",
            "▓▓▓▓▓▓▓▓▓▓▓▒░░░░░░░░░░",
            "▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░░░░░░",
            "▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░░░░░",
            "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░░░░",
            "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░░░",
            "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░░",
            "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░",
            "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░",
            "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░",
            "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░",
            "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒",
            "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        ]

        # Ekranı temizleme fonksiyonu
        def clear_console():
            os.system('cls' if os.name == 'nt' else 'clear')

        # Animasyonu oynatma
        for frame in frames:
            clear_console()
            
            # Kırmızı siren solda, mavi siren sağda
            print(" " * 10 + red + frame + reset + " " * 10 + blue + frame + reset)
            
            # ASCII arabalar yan yana
            print("\n" + " " * 6 + red + "    ____          ____    " + reset + "     " + blue + "    ____          ____    " + reset)
            print(" " * 6 + red + "  _/__|__\\____  _/__|__\\____ " + reset + "     " + blue + "  _/__|__\\____  _/__|__\\____ " + reset)
            print(" " * 6 + red + " |  _     _   ||  _     _   |" + reset + "     " + blue + " |  _     _   ||  _     _   |" + reset)
            print(" " * 6 + red + " '-(_)-------(_)-' -(_)-------(_)-" + reset + "     " + blue + " '-(_)-------(_)-' -(_)-------(_)-" + reset)

            time.sleep(0.1)

        # Renkleri değiştirerek ikinci geçiş
        for frame in frames:
            clear_console()
            
            # Mavi siren solda, kırmızı siren sağda
            print(" " * 10 + blue + frame + reset + " " * 10 + red + frame + reset)
            
            # ASCII arabalar yan yana
            print("\n" + " " * 6 + blue + "    ____          ____    " + reset + "     " + red + "    ____          ____    " + reset)
            print(" " * 6 + blue + "  _/__|__\\____  _/__|__\\____ " + reset + "     " + red + "  _/__|__\\____  _/__|__\\____ " + reset)
            print(" " * 6 + blue + " |  _     _   ||  _     _   |" + reset + "     " + red + " |  _     _   ||  _     _   |" + reset)
            print(" " * 6 + blue + " '-(_)-------(_)-' -(_)-------(_)-" + reset + "     " + red + " '-(_)-------(_)-' -(_)-------(_)-" + reset)

            time.sleep(0.1)

   
    def Learn_TTL_Value(self, ip_address):
        icmp_packet = scapy.IP(dst=ip_address) / scapy.ICMP()
        answered, _ = scapy.sr(icmp_packet, timeout=2, verbose=0)

        if answered:
            for _, value in answered:
                print(f"[ ✔ ][snow] TTL Değeri:[/snow] {value.ttl}")
                return value.ttl
        else:
            print("[red]Hedefe ulaşılamıyor[/]")
            return None

    def Learn_Window_Size_With_SYN_Packet(self, ip_address):
        ports = [80, 443, 22, 21, 23, 53, 445]
        for dst_port in ports:
            src_port = random.randint(1024, 65535)
            ip_layer = scapy.IP(dst=ip_address)
            tcp_layer = scapy.TCP(sport=src_port, dport=dst_port, flags='S', seq=1000)
            packet = ip_layer / tcp_layer

            try:
                response = scapy.sr1(packet, timeout=2, verbose=False)
                if response and response.haslayer(scapy.TCP):
                    tcp_resp = response.getlayer(scapy.TCP)
                    window_size = tcp_resp.window

                    if tcp_resp.flags == 0x14:
                        continue
                    elif tcp_resp.flags == 0x12:
                        print(f"[snow][ ✔ ] Window Size : {window_size} [/snow]")
                        return window_size
            except PermissionError:
                print("[red]Yönetici olarak çalıştırmalısın![/red]")
            except Exception as e:
                print(f"[red]Hata: {e}[/red]")
        return None

    def Os_Detection(self, ip_address):
        ttl_value = self.Learn_TTL_Value(ip_address)
        window_size_value = self.Learn_Window_Size_With_SYN_Packet(ip_address)

        if ttl_value is None or window_size_value is None:
            print("[red]İşletim sistemi tespit edilemedi.[/red]")
            return 

        if 0 < ttl_value <= 64:
            if window_size_value in [29200, 8760, 14600, 5792, 65535]:
                print("[green]OS: OpenBSD / Modern Linux Dist.[/green]")
            elif window_size_value == 5840:
                print("[green]OS: Linux 2.4.x - 2.6.x[/green]")
            elif window_size_value in [16384, 32768]:
                print("[green]OS: OpenBSD Or NetBSD[/green]")
            elif window_size_value == 65535:
                print("[green]OS: FreeBSD veya macOS olabilir[/green]")
            else:
                print("[yellow]OS: Unix/Linux Türevi (kesin değil)[/yellow]")

        elif 65 <= ttl_value <= 128:
            if window_size_value in [8192, 16384, 65535, 62240]:
                print("[blue]🪟 OS: Windows[/blue]")
            else:
                print("[yellow]OS: Muhtemelen Windows ama emin değiliz[/yellow]")

        elif 129 <= ttl_value <= 255:
            print("[cyan]OS: Cisco Router / Ağ Cihazı olabilir[/cyan]")

        else:
            print("[yellow]❓ OS: Bilinmeyen[/yellow]")
    

    def get_open_closed_ports(self, ip_address):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080]
        result = {"open": [], "closed": []}

        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((ip_address, port))
                    result["open"].append(port)
            except:
                result["closed"].append(port)

        return result
    
    #Paket Gönderimi yapılıyor Ve Cevap Olarak SYN_ACK Bayrak Bilgisi Alınıyor 
    def send_flag_packets(self, ip_address, port):
        flags_to_test = ["S", "SA", "R", "F", "A", "FA", "PA", "RA"]
        responses = {}
        src_port = random.randint(1024, 65535)

        for flag in flags_to_test:
            ip_layer = scapy.IP(dst=ip_address)
            tcp_layer = scapy.TCP(sport=src_port, dport=port, flags=flag, seq=1000)
            packet = ip_layer / tcp_layer

            try:
                response = scapy.sr1(packet, timeout=2, verbose=0)
                if response and response.haslayer(scapy.TCP):
                    tcp_resp = response.getlayer(scapy.TCP)
                    responses[flag] = str(tcp_resp.flags)

                    if tcp_resp.flags == 0x12:  # SYN-ACK
                        ack_pkt = scapy.TCP(sport=src_port, dport=port, flags='A',
                                            seq=tcp_layer.seq + 1, ack=tcp_resp.seq + 1)
                        scapy.send(ip_layer / ack_pkt, verbose=0)
                else:
                    responses[flag] = "No Response"
            except PermissionError:
                print("[red]Yönetici olarak çalıştırmalısın![/red]")
                break
            except Exception as e:
                print(f"[red]Hata: {e}[/red]")

        return responses

    def flag_response(self, ip_address):
        ports_info = self.get_open_closed_ports(ip_address)
        open_ports = ports_info["open"]
        closed_ports = ports_info["closed"]

        if not open_ports or not closed_ports:
            print("[red]Yeterli açık veya kapalı port bulunamadı.[/red]")
            return

        open_responses = {}
        closed_responses = {}

        print("[snow]\n[ ✔ ] Response For Open Ports :[/snow]")
        for port in open_ports:
            responses = self.send_flag_packets(ip_address, port)
            open_responses[port] = responses
            output = f"[snow][ ✔ ][/snow](Port : {port} " + "  ".join([f"{flag} → {res}" for flag, res in responses.items()]) + ")"
            print(output)

        print("[snow]\n[ ✔ ] Response For Closed Ports:[/snow]")
        for port in closed_ports:
            responses = self.send_flag_packets(ip_address, port)
            closed_responses[port] = responses
            output = f"[snow][ ✔ ][/snow](Port : {port} " + "  ".join([f"{flag} → {res}" for flag, res in responses.items()]) + ")"
            print(output)

        for open_port in open_ports:
            for closed_port in closed_ports:
                open_flags = open_responses[open_port]
                closed_flags = closed_responses[closed_port]
                print(f"[snow][ İ ]Open Port  {open_port} and  Closed Port {closed_port} For OS Analyze:[/snow]")
                self.analyze_os_from_flags(open_flags, closed_flags)

    def analyze_os_from_flags(self, open_flags, closed_flags):
        score = {}

        if open_flags.get("F") == "No Response" and closed_flags.get("F") == "RST":
            score["Linux/BSD"] = score.get("Linux/BSD", 0) + 1

        if open_flags.get("A") == "RST" and closed_flags.get("A") == "RST":
            score["Linux/BSD"] = score.get("Linux/BSD", 0) + 1

        if open_flags.get("F") == "RST" and closed_flags.get("F") == "RST":
            score["Windows"] = score.get("Windows", 0) + 1

        if open_flags.get("A") == "RST" and closed_flags.get("A") == "RST":
            score["Windows"] = score.get("Windows", 0) + 1

        if closed_flags.get("S") == "RST" and closed_flags.get("F") == "RST":
            score["Windows"] = score.get("Windows", 0) + 1

        if all(v == "No Response" for v in closed_flags.values()):
            score["Firewall veya Router"] = 1

        if score:
            os_guess = max(score, key=score.get)
            print(f"\n[snow][ ✔ ] Guess OS : {os_guess}[/snow]")
        else:
            print("[yellow][ ? ] Can't Guess Need More Flags Info [/yellow]")



   
    
    def One_Open_One_Closed_For_Alot_Port_Info(self,ip_address):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080]
        result = {"Open_Ports": [], "Closed_Ports": []}

        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((ip_address, port))
                    result["Open_Ports"].append(port)
            except:
                result["Closed_Ports"].append(port)

        return result

    def TCP_Option_Analyze(self,ip_address):
        Dict = self.One_Open_One_Closed_For_Alot_Port_Info(ip_address)
        Open_Ports = Dict["Open_Ports"]
        Tc_Options_Default_Value =[
            ("MSS", 1460),# Maximum Segment Size: Karşı tarafın alabileceği en büyük TCP veri segmenti.
            ("WScale", 10),#Window Scale değeri 8 → TCP pencere boyutunu 2⁸ = 256 ile çar anlamına gelir.
            ("SAckOK", b""),#b'' boş çünkü sadece desteklenip desteklenmediği belirtilir, veri taşımaz.
            ("Timestamp", (123, 0)),#123: sender timestamp (zaman sayacı gibi) 0 Geri Dönen Time Stap Bilgisi
            ("NOP", None),#No Operation: TCP opsiyonları hizalamak için kullanılır (padding gibi)
            ("NOP", None)
        ]
        print(f"[snow][ ✔ ] Ports Status For TCP Info : {Dict} [/snow]")

        if not Open_Ports:
            print("[yellow]There is no open port !!!!. Çıkılıyor.[/yellow]")
            return
        

        for dst_port in Open_Ports:
            src_port = random.randint(1024, 65535)
            ip = scapy.IP(dst=ip_address)
            syn = scapy.TCP( #default options Değerleri Göndererek Daha Fazla Bilgi almaya Çalışıyoruz 
            sport=src_port,
            dport=dst_port,
            flags="S",
            seq=1000,
            options=Tc_Options_Default_Value
            
    )
            print(f"[snow][ ✔ ] Sended Options Info :  {Tc_Options_Default_Value} [/snow]")
            pkt = ip / syn

            try:
                response = scapy.sr1(pkt, timeout=2, verbose=0)

                if response and response.haslayer(scapy.TCP):
                    tcp_layer = response.getlayer(scapy.TCP)

                    if tcp_layer.flags == 0x12:  # SYN-ACK döndüyse
                        options = tcp_layer.options
                        print(f"[ ✔ ] {ip_address}:{dst_port} → TCP Opsiyonları: {options}")

                        # Handshake tamamlamak için ACK gönder
                        ack = scapy.TCP(sport=src_port, dport=dst_port, flags='A',
                                        seq=syn.seq + 1, ack=tcp_layer.seq + 1)
                        scapy.send(ip / ack, verbose=0)
                    else:
                        print(f"[red][ - ][/red] {ip_address}:{dst_port} → SYN-ACK alınamadı.")
                else:
                    print(f"[red][ - ][/red] {ip_address}:{dst_port} → Hiç cevap gelmedi.")

            except PermissionError:
                print("[red]Yönetici olarak çalıştırmalısın![/red]")
            except Exception as e:
                print(f"[red]Hata: {e}[/red]")

    def guess_os_from_tcp_options(self,options):
        if ('MSS', 65495) in options and ('WScale', 8) in options and ('SAckOK', b'') in options:
            return "Windows 10 veya sonrası"
        elif ('MSS', 1460) in options and ('WScale', 2) in options:
            return "Linux 2.4/2.6"
        elif ('MSS', 1380) in options:
            return "Cisco IOS"
        elif ('MSS', 1460) in options and ('WScale', 0) in options:
            return "Windows XP/2003"
        else:
            return "Bilinmeyen OS"

if __name__ == '__main__':
    ip_address = input(f"      [İ][snow][/snow]Please Enter IPv4 Address : ")
    finder = OsFinder(ip_address)
    finder()
    
    


    
