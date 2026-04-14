import scapy.all as scapy

pcap_file = "file.pcap" # Đổi tên cho đúng file của bạn
output_file = "fixed_video.h264"

packets = scapy.rdpcap(pcap_file)
rtp_packets = []

print("Đang thu thập và sắp xếp gói tin...")

for pkt in packets:
    if pkt.haslayer(scapy.UDP) and len(pkt[scapy.UDP].payload) >= 12:
        payload = bytes(pkt[scapy.UDP].payload)
        # Lấy Sequence Number từ RTP Header (byte thứ 2 và 3)
        seq_num = int.from_bytes(payload[2:4], byteorder='big')
        rtp_packets.append((seq_num, payload[12:]))

# Sắp xếp theo Sequence Number
rtp_packets.sort(key=lambda x: x[0])

print(f"Đã tìm thấy {len(rtp_packets)} gói tin RTP. Đang ghép...")

with open(output_file, "wb") as f:
    for seq, payload in rtp_packets:
        if not payload: continue
        
        nal_type = payload[0] & 0x1F
        
        if 1 <= nal_type <= 23:
            f.write(b"\x00\x00\x00\x01" + payload)
        elif nal_type == 28: # FU-A (Gói bị chia nhỏ)
            fu_header = payload[1]
            if fu_header & 0x80: # Start bit
                reconstructed_nal_header = bytes([(payload[0] & 0xE0) | (fu_header & 0x1F)])
                f.write(b"\x00\x00\x00\x01" + reconstructed_nal_header + payload[2:])
            else:
                f.write(payload[2:])

print(f"Hoàn thành! File đã lưu tại: {output_file}")