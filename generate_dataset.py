"""
Sample Dataset Generator
Creates synthetic network traffic data for testing and demonstration.
Generates both normal traffic and various attack patterns.
"""

import random
from datetime import datetime, timedelta
from scapy.all import IP, TCP, UDP, ICMP, wrpcap
import time


class TrafficGenerator:
    """
    Generates synthetic network traffic for testing.
    Creates realistic patterns including normal traffic and attacks.
    """
    
    def __init__(self):
        """Initialize traffic generator."""
        self.packets = []
        
        # Common IP pools
        self.internal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
        self.external_ips = [f"8.8.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(20)]
        
        # Common ports
        self.common_ports = [80, 443, 22, 53, 21, 25, 110, 143, 3306, 5432]
    
    def generate_normal_traffic(self, count: int = 100):
        """
        Generate normal network traffic.
        
        Args:
            count: Number of packets to generate
        """
        print(f"Generating {count} normal traffic packets...")
        
        for _ in range(count):
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.external_ips)
            dst_port = random.choice(self.common_ports)
            src_port = random.randint(30000, 60000)
            
            # Randomly choose protocol
            protocol = random.choice(['TCP', 'UDP', 'ICMP'])
            
            if protocol == 'TCP':
                # Normal TCP traffic
                packet = IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=src_port,
                    dport=dst_port,
                    flags='S' if random.random() > 0.5 else 'A'
                )
            elif protocol == 'UDP':
                # Normal UDP traffic
                packet = IP(src=src_ip, dst=dst_ip) / UDP(
                    sport=src_port,
                    dport=dst_port
                )
            else:
                # ICMP ping
                packet = IP(src=src_ip, dst=dst_ip) / ICMP()
            
            self.packets.append(packet)
            
            # Small delay between packets
            if len(self.packets) % 10 == 0:
                time.sleep(0.01)
    
    def generate_port_scan(self, attacker_ip: str = None, target_ip: str = None, num_ports: int = 50):
        """
        Generate port scan attack pattern.
        
        Args:
            attacker_ip: Source IP (random if None)
            target_ip: Target IP (random if None)
            num_ports: Number of ports to scan
        """
        print(f"Generating port scan attack ({num_ports} ports)...")
        
        attacker_ip = attacker_ip or random.choice(self.external_ips)
        target_ip = target_ip or random.choice(self.internal_ips)
        
        for port in range(1, num_ports + 1):
            packet = IP(src=attacker_ip, dst=target_ip) / TCP(
                sport=random.randint(30000, 60000),
                dport=port,
                flags='S'
            )
            self.packets.append(packet)
            
            # Fast scanning
            if port % 10 == 0:
                time.sleep(0.001)
    
    def generate_syn_flood(self, attacker_ip: str = None, target_ip: str = None, 
                          target_port: int = 80, num_packets: int = 200):
        """
        Generate SYN flood attack pattern.
        
        Args:
            attacker_ip: Source IP
            target_ip: Target IP
            target_port: Target port
            num_packets: Number of SYN packets
        """
        print(f"Generating SYN flood attack ({num_packets} packets)...")
        
        attacker_ip = attacker_ip or random.choice(self.external_ips)
        target_ip = target_ip or random.choice(self.internal_ips)
        
        for _ in range(num_packets):
            packet = IP(src=attacker_ip, dst=target_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=target_port,
                flags='S'
            )
            self.packets.append(packet)
            
            # Very fast flooding
            if len(self.packets) % 20 == 0:
                time.sleep(0.001)
    
    def generate_ddos(self, target_ip: str = None, num_attackers: int = 30, 
                     packets_per_attacker: int = 50):
        """
        Generate distributed DDoS attack pattern.
        
        Args:
            target_ip: Target IP
            num_attackers: Number of attacking IPs
            packets_per_attacker: Packets from each attacker
        """
        print(f"Generating DDoS attack ({num_attackers} attackers)...")
        
        target_ip = target_ip or random.choice(self.internal_ips)
        
        # Generate random attacker IPs
        attackers = [f"{random.randint(1,223)}.{random.randint(1,255)}."
                    f"{random.randint(1,255)}.{random.randint(1,255)}" 
                    for _ in range(num_attackers)]
        
        for attacker in attackers:
            for _ in range(packets_per_attacker):
                packet = IP(src=attacker, dst=target_ip) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=80,
                    flags='S'
                )
                self.packets.append(packet)
    
    def generate_ip_scan(self, scanner_ip: str = None, num_ips: int = 100):
        """
        Generate IP scanning pattern.
        
        Args:
            scanner_ip: Scanner IP
            num_ips: Number of IPs to scan
        """
        print(f"Generating IP scan ({num_ips} IPs)...")
        
        scanner_ip = scanner_ip or random.choice(self.external_ips)
        
        for i in range(num_ips):
            target_ip = f"192.168.1.{i + 1}"
            packet = IP(src=scanner_ip, dst=target_ip) / ICMP()
            self.packets.append(packet)
            
            if i % 10 == 0:
                time.sleep(0.01)
    
    def generate_traffic_spike(self, source_ip: str = None, num_packets: int = 500):
        """
        Generate traffic spike pattern.
        
        Args:
            source_ip: Source IP
            num_packets: Number of packets in spike
        """
        print(f"Generating traffic spike ({num_packets} packets)...")
        
        source_ip = source_ip or random.choice(self.internal_ips)
        
        for _ in range(num_packets):
            dst_ip = random.choice(self.external_ips)
            dst_port = random.choice(self.common_ports)
            
            packet = IP(src=source_ip, dst=dst_ip) / TCP(
                sport=random.randint(30000, 60000),
                dport=dst_port,
                flags='A'
            )
            self.packets.append(packet)
    
    def save_to_pcap(self, filename: str):
        """
        Save generated packets to PCAP file.
        
        Args:
            filename: Output PCAP filename
        """
        if not self.packets:
            print("No packets to save!")
            return
        
        print(f"Saving {len(self.packets)} packets to {filename}...")
        wrpcap(filename, self.packets)
        print(f"PCAP file saved: {filename}")
    
    def clear_packets(self):
        """Clear all generated packets."""
        self.packets = []
    
    def get_packet_count(self) -> int:
        """Get current number of packets."""
        return len(self.packets)


def create_demo_dataset():
    """Create a comprehensive demo dataset with mixed traffic."""
    generator = TrafficGenerator()
    
    print("=" * 60)
    print("Creating Demo Network Traffic Dataset")
    print("=" * 60)
    
    # Normal traffic (baseline)
    generator.generate_normal_traffic(500)
    
    # Various attack patterns
    generator.generate_port_scan(num_ports=30)
    generator.generate_normal_traffic(50)
    
    generator.generate_syn_flood(num_packets=150)
    generator.generate_normal_traffic(50)
    
    generator.generate_ip_scan(num_ips=80)
    generator.generate_normal_traffic(50)
    
    generator.generate_ddos(num_attackers=25, packets_per_attacker=40)
    generator.generate_normal_traffic(50)
    
    generator.generate_traffic_spike(num_packets=300)
    generator.generate_normal_traffic(100)
    
    # Save to file
    generator.save_to_pcap('data/demo_traffic.pcap')
    
    print("\n" + "=" * 60)
    print(f"Demo dataset created successfully!")
    print(f"Total packets: {generator.get_packet_count()}")
    print(f"File: data/demo_traffic.pcap")
    print("=" * 60)
    
    return generator


def create_normal_baseline():
    """Create a dataset of only normal traffic for model training."""
    generator = TrafficGenerator()
    
    print("=" * 60)
    print("Creating Normal Traffic Baseline")
    print("=" * 60)
    
    generator.generate_normal_traffic(1000)
    generator.save_to_pcap('data/baseline_traffic.pcap')
    
    print("\n" + "=" * 60)
    print(f"Baseline dataset created!")
    print(f"Total packets: {generator.get_packet_count()}")
    print(f"File: data/baseline_traffic.pcap")
    print("=" * 60)
    
    return generator


def create_attack_only():
    """Create a dataset of only attacks for testing detection."""
    generator = TrafficGenerator()
    
    print("=" * 60)
    print("Creating Attack-Only Dataset")
    print("=" * 60)
    
    generator.generate_port_scan(num_ports=50)
    generator.generate_syn_flood(num_packets=200)
    generator.generate_ip_scan(num_ips=100)
    generator.generate_ddos(num_attackers=30, packets_per_attacker=50)
    
    generator.save_to_pcap('data/attacks_only.pcap')
    
    print("\n" + "=" * 60)
    print(f"Attack dataset created!")
    print(f"Total packets: {generator.get_packet_count()}")
    print(f"File: data/attacks_only.pcap")
    print("=" * 60)
    
    return generator


if __name__ == "__main__":
    import os
    
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)
    
    print("\n🔧 Network Traffic Dataset Generator\n")
    
    print("Select dataset type:")
    print("1. Demo dataset (mixed traffic)")
    print("2. Normal baseline (for training)")
    print("3. Attack-only (for testing)")
    print("4. All of the above")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == '1':
        create_demo_dataset()
    elif choice == '2':
        create_normal_baseline()
    elif choice == '3':
        create_attack_only()
    elif choice == '4':
        create_normal_baseline()
        print("\n")
        create_attack_only()
        print("\n")
        create_demo_dataset()
    else:
        print("Invalid choice!")
    
    print("\n✅ Dataset generation complete!")
