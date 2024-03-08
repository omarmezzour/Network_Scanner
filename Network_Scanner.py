import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
from scapy.all import Ether, DHCP, sniff
import socket
from threading import Thread
import ipinfo
import time

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner App")
        self.root.geometry("400x300")

        self.create_widgets()

    def create_widgets(self):
        label = tk.Label(self.root, text="Select an action:")
        label.pack(pady=10)

        port_scan_button = tk.Button(self.root, text="1- Port Scan", command=self.port_scan)
        port_scan_button.pack()

        geo_locate_button = tk.Button(self.root, text="2- GEOLOCATE IP", command=self.geo_locate)
        geo_locate_button.pack()

        dhcp_listener_button = tk.Button(self.root, text="3- DHCP Listener", command=self.dhcp_listener)
        dhcp_listener_button.pack()

    def port_scan(self):
        host = simpledialog.askstring("Input", "Enter the host:")
        port_range = simpledialog.askstring("Input", "Enter the ports/range:")
        start_port, end_port = map(int, port_range.split("-"))
        ports = [p for p in range(start_port, end_port + 1)]

        result = self.scan_ports(host, ports)

        messagebox.showinfo("Scan Results", result)

    def geo_locate(self):
        geotarget = simpledialog.askstring("Input", "What IP would you like to geolocate?")
        access_token = '58a0d309242449'
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails(geotarget)

        result = f"Geolocation for IP {geotarget}:\n"
        for key, value in details.all.items():
            result += f"{key}: {value}\n"

        messagebox.showinfo("Geolocation Results", result)

    def dhcp_listener(self):
        self.waiting_window = tk.Toplevel(self.root)
        self.waiting_window.title("Please wait...")
        label = tk.Label(self.waiting_window, text="Listening for DHCP requests. Please wait...")
        label.pack(pady=10)

        def print_packet(packet):
            target_mac, requested_ip, hostname, vendor_id = [None] * 4
            if packet.haslayer(Ether):
                target_mac = packet.getlayer(Ether).src
            dhcp_options = packet[DHCP].options
            for item in dhcp_options:
                try:
                    label, value = item
                except ValueError:
                    continue
                if label == "requested_addr":
                    requested_ip = value
                elif label == "hostname":
                    hostname = value.decode()
                elif label == "vendor_class_id":
                    vendor_id = value.decode()

            if target_mac and vendor_id and hostname and requested_ip:
                time_now = time.strftime("[%Y-%m-%d  - %H:%M:%S]")
                result = f"{time_now}: {target_mac} - {hostname} / {vendor_id} requested {requested_ip}"
                self.show_dhcp_result(result)

        dhcp_thread = Thread(target=self.start_dhcp_sniffing, args=(print_packet,))
        dhcp_thread.start()

    def start_dhcp_sniffing(self, callback):
        sniff(prn=callback, filter='udp and (port 67 or port 68)')

    def show_dhcp_result(self, result):
        self.waiting_window.destroy()
        messagebox.showinfo("DHCP Listener Results", result)

    def scan_ports(self, host, ports):
        open_ports = []
        for port in ports:
            try:
                s = socket.socket()
                s.connect((host, port))
            except:
                open_ports.append((port, "Closed"))
            else:
                open_ports.append((port, "Open"))
            finally:
                s.close()

        result = "Scan Results:\n"
        for port, status in open_ports:
            result += f"Port {port}: {status}\n"

        return result

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
