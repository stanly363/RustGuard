import os
import statistics
from collections import defaultdict
import pandas as pd
from scapy.all import rdpcap, TCP, UDP, IP

def process_pcap(pcap_file_path):
    """
    Processes a single PCAP file and extracts flow features.
    """
    flows = defaultdict(list)
    
    # 1. Read packets and group them into flows
    for packet in rdpcap(pcap_file_path):
        if IP in packet and (TCP in packet or UDP in packet):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            src_port = packet.sport
            dst_port = packet.dport

            # Sort IPs and ports to uniquely identify a bidirectional flow
            flow_key_part1 = tuple(sorted(((src_ip, src_port), (dst_ip, dst_port))))
            flow_key = flow_key_part1 + (proto,)
            
            # Store packet details
            flows[flow_key].append({
                'timestamp': float(packet.time),
                'len': len(packet),
                'src': (src_ip, src_port),
                'flags': packet[TCP].flags if TCP in packet else 0,
                'header_len': packet[IP].ihl * 4, # IP header length in bytes
                'window': packet[TCP].window if TCP in packet else 0
            })

    # 2. Calculate features for each flow
    feature_list = []
    for key, packets_in_flow in flows.items():
        if len(packets_in_flow) < 2:
            continue  # Skip flows with less than 2 packets

        packets_in_flow.sort(key=lambda x: x['timestamp'])
        
        # Determine forward/backward direction based on the first packet
        fwd_dir = packets_in_flow[0]['src']
        fwd_packets = [p for p in packets_in_flow if p['src'] == fwd_dir]
        bwd_packets = [p for p in packets_in_flow if p['src'] != fwd_dir]

        # Skip if flow is unidirectional
        if not fwd_packets or not bwd_packets:
            continue

        # --- Feature Calculations ---
        
        # Dst Port and Protocol
        dst_port = key[1][1] if key[0] == fwd_dir else key[0][1]
        protocol = key[2]

        # Flow Duration (microseconds)
        flow_duration = (packets_in_flow[-1]['timestamp'] - packets_in_flow[0]['timestamp']) * 1_000_000

        # Packet Length Stats
        fwd_pkt_lengths = [p['len'] for p in fwd_packets]
        bwd_pkt_lengths = [p['len'] for p in bwd_packets]
        fwd_packet_len_max = max(fwd_pkt_lengths) if fwd_pkt_lengths else 0
        fwd_packet_len_std = statistics.stdev(fwd_pkt_lengths) if len(fwd_pkt_lengths) > 1 else 0
        bwd_packet_len_max = max(bwd_pkt_lengths) if bwd_pkt_lengths else 0
        bwd_packet_len_mean = statistics.mean(bwd_pkt_lengths) if bwd_pkt_lengths else 0
        bwd_packet_len_std = statistics.stdev(bwd_pkt_lengths) if len(bwd_pkt_lengths) > 1 else 0

        # Inter-Arrival Time (IAT) Stats
        all_timestamps = [p['timestamp'] for p in packets_in_flow]
        fwd_timestamps = [p['timestamp'] for p in fwd_packets]
        flow_iat = [ (all_timestamps[i] - all_timestamps[i-1]) * 1_000_000 for i in range(1, len(all_timestamps)) ]
        fwd_iat = [ (fwd_timestamps[i] - fwd_timestamps[i-1]) * 1_000_000 for i in range(1, len(fwd_timestamps)) ]

        flow_iat_mean = statistics.mean(flow_iat) if flow_iat else 0
        flow_iat_max = max(flow_iat) if flow_iat else 0
        flow_iat_min = min(flow_iat) if flow_iat else 0
        fwd_iat_mean = statistics.mean(fwd_iat) if fwd_iat else 0
        fwd_iat_max = max(fwd_iat) if fwd_iat else 0

        # Header Length
        fwd_header_len = sum(p['header_len'] for p in fwd_packets)

        # Packets per Second (Derived)
        duration_sec = flow_duration / 1_000_000
        flow_packets_per_second = len(packets_in_flow) / duration_sec if duration_sec > 0 else 0
        fwd_packets_per_second = len(fwd_packets) / duration_sec if duration_sec > 0 else 0
        bwd_packets_per_second = len(bwd_packets) / duration_sec if duration_sec > 0 else 0

        # TCP Flag Counts
        rst_flag_count = sum(1 for p in packets_in_flow if p['flags'] & 0x04)
        psh_flag_count = sum(1 for p in packets_in_flow if p['flags'] & 0x08)
        ack_flag_count = sum(1 for p in packets_in_flow if p['flags'] & 0x10)
        urg_flag_count = sum(1 for p in packets_in_flow if p['flags'] & 0x20)
        ece_flag_count = sum(1 for p in packets_in_flow if p['flags'] & 0x40)

        # Initial Window Bytes
        init_win_bytes_forward = fwd_packets[0]['window']
        init_win_bytes_backward = bwd_packets[0]['window']

        feature_list.append({
            'Dst Port': dst_port,
            'Protocol': protocol,
            'Flow Duration': flow_duration,
            'Fwd Pkt Len Max': fwd_packet_len_max,
            'Fwd Pkt Len Std': fwd_packet_len_std,
            'Bwd Pkt Len Max': bwd_packet_len_max,
            'Bwd Pkt Len Mean': bwd_packet_len_mean,
            'Bwd Pkt Len Std': bwd_packet_len_std,
            'Flow Pkts/s': flow_packets_per_second,
            'Flow IAT Mean': flow_iat_mean,
            'Flow IAT Max': flow_iat_max,
            'Flow IAT Min': flow_iat_min,
            'Fwd IAT Mean': fwd_iat_mean,
            'Fwd IAT Max': fwd_iat_max,
            'Fwd Header Len': fwd_header_len,
            'Fwd Pkts/s': fwd_packets_per_second,
            'Bwd Pkts/s': bwd_packets_per_second,
            'RST Flag Cnt': rst_flag_count,
            'PSH Flag Cnt': psh_flag_count,
            'ACK Flag Cnt': ack_flag_count,
            'URG Flag Cnt': urg_flag_count,
            'ECE Flag Cnt': ece_flag_count,
            'Init Fwd Win Byts': init_win_bytes_forward,
            'Init Bwd Win Byts': init_win_bytes_backward,
            'Fwd Seg Size Min': 20.0 # Mimicking the constant from your Rust code
        })
    return feature_list


# --- Main execution logic ---
if __name__ == "__main__":
    benign_path = "pcap_samples/benign"
    malicious_path = "pcap_samples/malicious"
    
    all_features = []
    
    # Process benign files
    print("Processing benign PCAPs...")
    for filename in os.listdir(benign_path):
        if filename.endswith(('.pcap', '.pcapng')):
            filepath = os.path.join(benign_path, filename)
            features = process_pcap(filepath)
            for f in features:
                f['Label'] = 'Benign'
            all_features.extend(features)
            
    # Process malicious files
    print("Processing malicious PCAPs...")
    for filename in os.listdir(malicious_path):
        if filename.endswith(('.pcap', '.pcapng')):

            label_name = os.path.splitext(filename)[0]
            
            filepath = os.path.join(malicious_path, filename)
            features = process_pcap(filepath)
            for f in features:
                f['Label'] = label_name # Assign the specific attack name
            all_features.extend(features)
            
    # Create a DataFrame and save to CSV
    df = pd.DataFrame(all_features)
    
    # Convert protocol number to float as in your Rust code
    df['Protocol'] = df['Protocol'].apply(lambda x: 6.0 if x == 6 else (17.0 if x == 17 else 0.0))

    output_csv_path = 'pcap_features.csv'
    df.to_csv(output_csv_path, index=False)
    
    print(f"\nProcessing complete. {len(df)} flows extracted.")
    print(f"Features saved to {output_csv_path}")
    print("\nSample of the first 5 rows:")
    print(df.head())