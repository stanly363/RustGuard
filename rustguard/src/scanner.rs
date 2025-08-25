use pnet::datalink::{self, Channel};
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::task;
use serde::Serialize;
// --- Restored imports for the original scanning technique ---
use tokio::net::TcpStream;
use futures::stream::{self, StreamExt};

/// Holds the discovered information for a specific device.
#[derive(Serialize, Clone, Debug)]
pub struct DeviceInfo {
    pub ip_addr: IpAddr,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub open_ports: Option<Vec<u16>>,
    pub is_scanning: bool,
}

impl DeviceInfo {
    /// Creates a placeholder for a device that is about to be scanned.
    pub fn new_scanning(ip_addr: IpAddr) -> Self {
        DeviceInfo {
            ip_addr,
            hostname: None,
            mac_address: None,
            open_ports: None,
            is_scanning: true,
        }
    }
}

/// Scans a target IP address for detailed information.
pub async fn scan_ip(target_ip: IpAddr, interface_name: &str) -> DeviceInfo {
    let (hostname_res, ports_res, mac_res) = tokio::join!(
        task::spawn_blocking(move || get_hostname(target_ip)),
        // FIX: The restored scan_ports is async, so we call it directly
        scan_ports(target_ip),
        get_mac_address(target_ip, interface_name.to_string())
    );

    let mut open_ports = ports_res; // The result is a simple Vec<u16>
    open_ports.sort();

    DeviceInfo {
        ip_addr: target_ip,
        hostname: hostname_res.unwrap_or(None),
        mac_address: mac_res,
        open_ports: Some(open_ports),
        is_scanning: false,
    }
}

/// Performs a reverse DNS lookup to find the hostname.
fn get_hostname(ip: IpAddr) -> Option<String> {
    dns_lookup::lookup_addr(&ip).ok()
}


// 👇 --- THIS SECTION IS REVERTED TO THE ORIGINAL TECHNIQUE --- 👇

/// Scans all ports from 1 to 65535 using a TCP Connect Scan.
async fn scan_ports(target_ip: IpAddr) -> Vec<u16> {
    println!("Starting TCP Connect scan on {}", target_ip);
    const CONCURRENCY_LIMIT: usize = 1000;

    let scan_stream = stream::iter(1..=65535)
        .map(|port| check_port(target_ip, port))
        .buffer_unordered(CONCURRENCY_LIMIT);

    let open_ports: Vec<u16> = scan_stream
        .filter_map(|result| async move { result })
        .collect()
        .await;
    
    println!("TCP Connect scan on {} complete. Found {} open ports.", target_ip, open_ports.len());
    open_ports
}

/// Checks a single port by attempting a full TCP connection.
async fn check_port(ip: IpAddr, port: u16) -> Option<u16> {
    let timeout = Duration::from_millis(500); // A slightly longer timeout can be more reliable
    let socket_addr = SocketAddr::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(_)) => Some(port), // Connection successful = port is open
        _ => None,
    }
}


/// Sends an ARP request to get the MAC address for a target IP.
async fn get_mac_address(target_ip: IpAddr, interface_name: String) -> Option<String> {
    let target_ipv4 = match target_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Some("ARP not applicable for IPv6".to_string()),
    };

    let interfaces = datalink::interfaces();
    let Some(interface) = interfaces.into_iter().find(|iface| iface.name == interface_name) else {
        eprintln!("ARP Scan Debug: Could not find the specified interface '{}'.", interface_name);
        return None;
    };

    let Some(source_ipv4) = interface.ips.iter()
        .find_map(|ip| if let IpAddr::V4(ipv4) = ip.ip() { Some(ipv4) } else { None }) else {
            eprintln!("ARP Scan Debug: Interface {} has no source IPv4 address.", interface.name);
            return None;
        };

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Err(e) => {
            eprintln!("ARP Scan Debug: Failed to create channel for interface {}: {}. Try running as Administrator.", interface.name, e);
            return None;
        }
        _ => {
             eprintln!("ARP Scan Debug: Unsupported channel type for interface {}.", interface.name);
            return None;
        }
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut arp_buffer = [0u8; 28];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(pnet::util::MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(source_ipv4);
    arp_packet.set_target_hw_addr(pnet::util::MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ipv4);
    ethernet_packet.set_payload(arp_packet.packet());

    if let Some(Err(e)) = tx.send_to(ethernet_packet.packet(), None) {
        eprintln!("ARP Scan Debug: Failed to send ARP packet: {}", e);
        return None;
    }

    let timeout = Duration::from_secs(2);
    let start_time = std::time::Instant::now();
    while start_time.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth_packet) = EthernetPacket::new(packet) {
                    if eth_packet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth_packet.payload()) {
                            if arp.get_sender_proto_addr() == target_ipv4 {
                                return Some(arp.get_sender_hw_addr().to_string());
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("ARP Scan Debug: Error receiving packet: {}", e);
                return None
            }
        }
    }

    eprintln!("ARP Scan Debug: Timed out waiting for ARP reply from {}.", target_ip);
    None
}