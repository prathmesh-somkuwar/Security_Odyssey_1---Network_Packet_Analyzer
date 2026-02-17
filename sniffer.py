#!/usr/bin/env python3
"""
SENTINEL-X SIMPLE PACKET SNIFFER v1.0
====================================
3 files total: sniffer.py + dashboard.html + requirements.txt
Run: sudo python3 sniffer.py
"""

# === STANDARD LIBRARY (Built into Python) ===
import threading                           # Runs packet capture WHILE serving web pages
from collections import deque              # Stores recent 1000 packets (memory safe)
from datetime import datetime              # Creates timestamps like "14:30:25.123"
import scapy.all as scapy                  # CORE: Captures raw network packets (needs sudo)

# === WEB SERVER (pip installed packages) ===
from flask import Flask, render_template    # Flask: Web server | render_template: Loads HTML
from flask_socketio import SocketIO, emit   # SocketIO: Sends packets to browser instantly

# === SETTINGS (Easy to change) ===
app = Flask(__name__)                       # Creates Flask web app
socketio = SocketIO(app, cors_allowed_origins="*")  # Adds real-time WebSocket
packets = deque(maxlen=1000)                # Stores LAST 1000 packets only
clients_connected = 0                       # Counts browser tabs open

# === 1. AUTO FIND NETWORK INTERFACE ===
def find_network_card():                    # Finds your WiFi/Ethernet automatically
    """Scans all network cards, picks active one (wlan0/eth0)"""
    print("🔍 Scanning network interfaces...")
    interfaces = scapy.get_if_list()        # Gets list: ['lo', 'wlan0', 'eth0']
    
    for interface in interfaces:            # Loop through each network card
        if 'lo' not in interface.lower():   # Skip loopback (fake local traffic)
            try:
                ip_address = scapy.get_if_addr(interface)  # Get IP of this card
                if ip_address and not ip_address.startswith('127.'):  # Real IP?
                    print(f"   ✅ USING: {interface} (IP: {ip_address})")
                    return interface                  # Found working network card!
            except:
                continue                           # Skip broken cards
    
    print("⚠️  Using default interface")
    return scapy.conf.iface                  # Scapy's backup choice

# === 2. ANALYZE EACH PACKET ===
def analyze_packet(packet):                 # Called 1x PER packet by Scapy
    """Breaks down packet into useful info: IP, ports, protocol"""
    
    # Check if packet has IP layer (skip ARP/DNS noise)
    if not packet.haslayer(scapy.IP):       # No IP? Skip it
        return
    
    ip_layer = packet[scapy.IP]             # Extract complete IP header
    
    # Create packet summary (sent to browser)
    packet_info = {
        'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],  # "14:30:25.123"
        'src_ip': ip_layer.src,              # Who sent: "192.168.1.100"
        'dst_ip': ip_layer.dst,              # Who received: "8.8.8.8"
        'proto_num': ip_layer.proto,         # Raw number: 6=TCP, 17=UDP
        'proto_name': {                      # Human names
            1: 'ICMP', 6: 'TCP', 17: 'UDP'
        }.get(ip_layer.proto, 'OTHER'),
        'size': len(packet),                 # Total bytes
        'ttl': ip_layer.ttl                  # Hops left (network distance)
    }
    
    # TCP/UDP PORTS (Layer 4)
    if packet.haslayer(scapy.TCP):          # TCP packet found
        tcp_layer = packet[scapy.TCP]       # Get TCP header
        packet_info['src_port'] = tcp_layer.sport  # Source port (random high number)
        packet_info['dst_port'] = tcp_layer.dport  # Destination port (80, 443)
        packet_info['type'] = 'TCP'
    elif packet.haslayer(scapy.UDP):        # UDP packet
        udp_layer = packet[scapy.UDP]
        packet_info['src_port'] = udp_layer.sport
        packet_info['dst_port'] = udp_layer.dport
        packet_info['type'] = 'UDP'
    else:
        packet_info['ports'] = '-'          # No ports for ICMP/etc
        packet_info['type'] = packet_info['proto_name']
    
    # SECURITY ALERTS
    if packet_info['dst_ip'] in ['8.8.8.8', '1.1.1.1']:  # Google/Cloudflare DNS?
        print(f"🚨 DNS QUERY: {packet_info['src_ip']} → {packet_info['dst_ip']}")
    
    # SAVE PACKET + SEND TO BROWSER
    packets.append(packet_info)             # Add to memory buffer
    socketio.emit('packet', packet_info)    # Push to ALL open browser tabs

# === 3. WEB PAGE ROUTES ===
@app.route('/')
def show_dashboard():                       # Browser visits http://127.0.0.1:5000/
    """Sends HTML dashboard to browser"""
    return render_template('dashboard.html')  # Loads HTML file from templates/

# === 4. WEBSOCKET EVENTS (Browser ↔ Server) ===
@socketio.on('connect')                     # Browser opens webpage
def browser_connected():
    """New browser tab opened"""
    global clients_connected
    clients_connected += 1                   # Count browsers
    print(f"🌐 Browser #{clients_connected} connected")
    
    # Send last 50 packets to new browser
    recent_packets = list(packets)[-50:]
    emit('history', recent_packets)

@socketio.on('disconnect')                  # Browser closes tab
def browser_disconnected():
    """Browser tab closed"""
    global clients_connected
    clients_connected -= 1

# === 5. START EVERYTHING ===
if __name__ == '__main__':
    """Main program - runs when: sudo python3 sniffer.py"""
    
    # Find network card
    network_card = find_network_card()
    
    # Show startup screen
    print("\n" + "="*60)
    print("🚀 SENTINEL-X v1.0 - SIMPLE PACKET SNIFFER")
    print(f"📡 CAPTURING: {network_card}")
    print("🌐 DASHBOARD: http://127.0.0.1:5000")
    print("💡 TEST: ping 8.8.8.8")
    print("🛑 STOP: Ctrl+C")
    print("="*60)
    
    # Start packet capture (background)
    capture_thread = threading.Thread(       # New thread = background job
        target=scapy.sniff,                  # Scapy's capture function
        kwargs={
            'iface': network_card,           # Which network card
            'prn': analyze_packet,           # Call analyze_packet() per packet
            'filter': 'ip',                  # IP packets only
            'store': False                   # Don't save to disk
        },
        daemon=True                          # Thread dies when program stops
    )
    capture_thread.start()
    print("🔥 PACKET SNIFFER RUNNING")
    
    # Start web server (foreground)
    socketio.run(app, host='127.0.0.1', port=5000, debug=False)
