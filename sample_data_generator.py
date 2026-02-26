"""
Sample Data Generator
Creates realistic PCAP files with normal and malicious traffic for testing
"""

import random
import time
from scapy.all import IP, TCP, UDP, ICMP, wrpcap, Ether
from pathlib import Path
import config
from logger import logger

class TrafficGenerator:
    """
    Generates realistic network traffic for testing
    """
    
    def __init__(self):
        """Initialize traffic generator"""
        self.packets = []
        
        # Common IP ranges
        self.internal_ips = [f"192.168.1.{i}" for i in range(1, 50)]
        self.external_ips = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" 
                            for _ in range(20)]
        
        # Common ports
        self.common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432]
        
        logger.info("TrafficGenerator initialized")
    
    def generate_normal_traffic(self, count=1000):
        """
        Generate normal HTTP/HTTPS traffic
        
        Args:
            count: Number of packets to generate
        """
        logger.info(f"Generating {count} normal traffic packets...")
        
        for i in range(count):
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.external_ips)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443])
            
            # Create TCP packet
            pkt = (Ether() / 
                   IP(src=src_ip, dst=dst_ip) /
                   TCP(sport=src_port, dport=dst_port, flags='A') /
                   ("X" * random.randint(100, 1400)))
            
            self.packets.append(pkt)
            
            # Add response packet (bidirectional flow)
            if random.random() > 0.3:
                resp = (Ether() /
                       IP(src=dst_ip, dst=src_ip) /
                       TCP(sport=dst_port, dport=src_port, flags='A') /
                       ("Y" * random.randint(100, 1400)))
                self.packets.append(resp)
        
        logger.info(f"Generated {len(self.packets)} normal packets")
    
    def generate_port_scan(self, attacker_ip=None, target_ip=None, port_range=(1, 1024)):
        """
        Generate port scan attack pattern
        
        Args:
            attacker_ip: Source IP for scan
            target_ip: Target IP
            port_range: Range of ports to scan
        """
        attacker = attacker_ip or "192.168.1.100"
        target = target_ip or random.choice(self.external_ips)
        
        logger.info(f"Generating port scan: {attacker} -> {target}")
        
        # Scan ports
        for port in range(port_range[0], min(port_range[1] + 1, port_range[0] + 100)):
            pkt = (Ether() /
                   IP(src=attacker, dst=target) /
                   TCP(sport=random.randint(1024, 65535), dport=port, flags='S'))
            
            self.packets.append(pkt)
            
            # Some ports respond with RST
            if random.random() > 0.7:
                resp = (Ether() /
                       IP(src=target, dst=attacker) /
                       TCP(sport=port, dport=pkt[TCP].sport, flags='RA'))
                self.packets.append(resp)
        
        logger.info(f"Generated port scan with {port_range[1] - port_range[0]} ports")
    
    def generate_syn_flood(self, attacker_ip=None, target_ip=None, count=500):
        """
        Generate SYN flood attack
        
        Args:
            attacker_ip: Source IP
            target_ip: Target IP
            count: Number of SYN packets
        """
        attacker = attacker_ip or "192.168.1.200"
        target = target_ip or random.choice(self.external_ips)
        
        logger.info(f"Generating SYN flood: {attacker} -> {target} ({count} packets)")
        
        for i in range(count):
            pkt = (Ether() /
                   IP(src=attacker, dst=target) /
                   TCP(sport=random.randint(1024, 65535), dport=80, flags='S'))
            
            self.packets.append(pkt)
        
        logger.info(f"Generated {count} SYN packets")
    
    def generate_dns_traffic(self, count=100):
        """
        Generate DNS queries
        
        Args:
            count: Number of DNS packets
        """
        logger.info(f"Generating {count} DNS packets...")
        
        for i in range(count):
            src_ip = random.choice(self.internal_ips)
            dst_ip = "8.8.8.8"  # Google DNS
            
            pkt = (Ether() /
                   IP(src=src_ip, dst=dst_ip) /
                   UDP(sport=random.randint(1024, 65535), dport=53) /
                   ("DNS Query" + "X" * random.randint(20, 100)))
            
            self.packets.append(pkt)
    
    def generate_icmp_traffic(self, count=50):
        """
        Generate ICMP ping traffic
        
        Args:
            count: Number of ICMP packets
        """
        logger.info(f"Generating {count} ICMP packets...")
        
        for i in range(count):
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.external_ips)
            
            pkt = (Ether() /
                   IP(src=src_ip, dst=dst_ip) /
                   ICMP() /
                   ("X" * 56))
            
            self.packets.append(pkt)
            
            # Echo reply
            if random.random() > 0.2:
                resp = (Ether() /
                       IP(src=dst_ip, dst=src_ip) /
                       ICMP(type=0) /
                       ("X" * 56))
                self.packets.append(resp)
    
    def generate_large_transfer(self, count=200):
        """
        Generate large data transfer (anomalous packet sizes)
        
        Args:
            count: Number of packets
        """
        logger.info(f"Generating large data transfer ({count} packets)...")
        
        src_ip = random.choice(self.internal_ips)
        dst_ip = random.choice(self.external_ips)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(self.common_ports)
        
        for i in range(count):
            pkt = (Ether() /
                   IP(src=src_ip, dst=dst_ip) /
                   TCP(sport=src_port, dport=dst_port, flags='A') /
                   ("Z" * 1400))  # Large packets
            
            self.packets.append(pkt)
    
    def shuffle_packets(self):
        """Shuffle packets to simulate realistic timeline"""
        random.shuffle(self.packets)
        logger.info("Packets shuffled")
    
    def save_pcap(self, filename):
        """
        Save generated packets to PCAP file
        
        Args:
            filename: Output filename
        """
        if not self.packets:
            logger.warning("No packets to save")
            return
        
        filepath = Path(filename)
        wrpcap(str(filepath), self.packets)
        logger.info(f"Saved {len(self.packets)} packets to {filepath}")
    
    def clear(self):
        """Clear all generated packets"""
        self.packets = []
        logger.info("Packet buffer cleared")

def generate_sample_dataset(output_file=None):
    """
    Generate a comprehensive sample dataset
    
    Args:
        output_file: Output PCAP filename
    """
    output = output_file or (config.DATA_DIR / "sample_traffic.pcap")
    
    print("=" * 60)
    print("Sample Network Traffic Generator")
    print("=" * 60)
    
    generator = TrafficGenerator()
    
    # Generate different traffic types
    print("\n1. Generating normal HTTP/HTTPS traffic...")
    generator.generate_normal_traffic(count=800)
    
    print("2. Generating DNS queries...")
    generator.generate_dns_traffic(count=100)
    
    print("3. Generating ICMP ping traffic...")
    generator.generate_icmp_traffic(count=50)
    
    print("4. Generating port scan attack...")
    generator.generate_port_scan(
        attacker_ip="192.168.1.100",
        target_ip="10.50.30.10",
        port_range=(1, 100)
    )
    
    print("5. Generating SYN flood attack...")
    generator.generate_syn_flood(
        attacker_ip="192.168.1.200",
        target_ip="10.50.30.20",
        count=300
    )
    
    print("6. Generating large data transfer (anomalous)...")
    generator.generate_large_transfer(count=150)
    
    # Shuffle to simulate realistic timing
    print("\n7. Shuffling packets...")
    generator.shuffle_packets()
    
    # Save
    print(f"8. Saving to {output}...")
    generator.save_pcap(output)
    
    print("\n" + "=" * 60)
    print(f"✓ Sample dataset created: {output}")
    print(f"  Total packets: {len(generator.packets)}")
    print("=" * 60)
    
    return output

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate sample network traffic')
    parser.add_argument('-o', '--output', default=None,
                       help='Output PCAP file (default: data/sample_traffic.pcap)')
    parser.add_argument('-n', '--normal', type=int, default=800,
                       help='Number of normal packets')
    parser.add_argument('--port-scan', action='store_true',
                       help='Include port scan attack')
    parser.add_argument('--syn-flood', action='store_true',
                       help='Include SYN flood attack')
    
    args = parser.parse_args()
    
    if args.output is None and args.normal == 800:
        # Generate full sample dataset
        generate_sample_dataset()
    else:
        # Custom generation
        generator = TrafficGenerator()
        
        if args.normal > 0:
            generator.generate_normal_traffic(count=args.normal)
        
        if args.port_scan:
            generator.generate_port_scan()
        
        if args.syn_flood:
            generator.generate_syn_flood()
        
        output = args.output or (config.DATA_DIR / "custom_traffic.pcap")
        generator.save_pcap(output)
        print(f"Generated {len(generator.packets)} packets -> {output}")
