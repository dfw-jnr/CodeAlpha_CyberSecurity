"""Build a tiny Ethernet/IPv4/TCP PCAP without sending network traffic."""
import argparse
import socket
import struct
from pathlib import Path


def internet_checksum(data):
    """Return the 16-bit Internet checksum for an IPv4/TCP header."""
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b""):
    """Create a checksummed Ethernet IPv4 TCP packet for offline analysis."""
    source = socket.inet_aton(src_ip)
    destination = socket.inet_aton(dst_ip)
    tcp_offset = 5
    tcp_header = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack,
        (tcp_offset << 12) | flags, 65535, 0, 0,
    )
    pseudo_header = struct.pack("!4s4sBBH", source, destination, 0, 6, len(tcp_header) + len(payload))
    tcp_checksum = internet_checksum(pseudo_header + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack,
        (tcp_offset << 12) | flags, 65535, tcp_checksum, 0,
    )

    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0x4000, 64, 6, 0, source, destination)
    ip_checksum = internet_checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0x4000, 64, 6, ip_checksum, source, destination)

    # Locally administered unicast MAC addresses, used only as sample bytes.
    client_mac = bytes.fromhex("020000000001")
    server_mac = bytes.fromhex("020000000002")
    if src_ip == "198.51.100.10":
        destination_mac, source_mac = server_mac, client_mac
    else:
        destination_mac, source_mac = client_mac, server_mac
    ethernet = destination_mac + source_mac + bytes.fromhex("0800")
    return ethernet + ip_header + tcp_header + payload


def write_pcap(destination):
    client_ip, server_ip = "198.51.100.10", "192.0.2.20"
    client_port, server_port = 41000, 80
    packets = [
        make_tcp_packet(client_ip, server_ip, client_port, server_port, 1000, 0, 0x02),
        make_tcp_packet(server_ip, client_ip, server_port, client_port, 5000, 1001, 0x12),
        make_tcp_packet(client_ip, server_ip, client_port, server_port, 1001, 5001, 0x10),
        make_tcp_packet(
            client_ip, server_ip, client_port, server_port, 1001, 5001, 0x18,
            b"GET /.env HTTP/1.1\r\nHost: lab.example\r\nUser-Agent: CodeAlpha-Lab\r\nConnection: close\r\n\r\n",
        ),
    ]
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as capture:
        # Classic PCAP global header: little-endian, Ethernet link type.
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            capture.write(struct.pack("<IIII", 1_700_000_000 + index, 0, len(packet), len(packet)))
            capture.write(packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("lab_test.pcap"), help="where to write the synthetic PCAP")
    args = parser.parse_args()
    write_pcap(args.output)
    print(f"Wrote {args.output} with four synthetic packets; no network traffic was sent.")


if __name__ == "__main__":
    main()
