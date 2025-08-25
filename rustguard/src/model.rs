use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;
use std::time::Instant;
use super::state::{Flow, NetworkState, CicFeatureVector};

pub fn handle_packet(data: &[u8], state: &mut NetworkState, local_ip_to_ignore: Option<IpAddr>) {
    if let Some(eth) = EthernetPacket::new(data) {
        let (src_ip, dst_ip, protocol, payload, ip_header_len) = match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                    (
                        IpAddr::V4(ipv4.get_source()),
                        IpAddr::V4(ipv4.get_destination()),
                        ipv4.get_next_level_protocol().0,
                        ipv4.payload().to_vec(),
                        (ipv4.get_header_length() * 4) as u64,
                    )
                } else { return; }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                    (
                        IpAddr::V6(ipv6.get_source()),
                        IpAddr::V6(ipv6.get_destination()),
                        ipv6.get_next_header().0,
                        ipv6.payload().to_vec(),
                        40,
                    )
                } else { return; }
            }
            _ => return,
        };

        if let Some(local_ip) = local_ip_to_ignore {
            if src_ip == local_ip {
                return;
            }
        }

        handle_transport_protocol(src_ip, dst_ip, protocol, &payload, ip_header_len, data.len() as u64, state);
    }
}

fn handle_transport_protocol(src_ip: IpAddr, dst_ip: IpAddr, protocol: u8, payload: &[u8], ip_header_len: u64, packet_size: u64, state: &mut NetworkState) {
    match protocol {
        6 => { // TCP
            if let Some(tcp) = TcpPacket::new(payload) {
                let src_port = tcp.get_source();
                let dst_port = tcp.get_destination();
                let flow_id = (src_ip, dst_ip, src_port, dst_port, "tcp".to_string());
                let reverse_flow_id = (dst_ip, src_ip, dst_port, src_port, "tcp".to_string());

                let is_fwd = state.active_flows.contains_key(&flow_id) || !state.active_flows.contains_key(&reverse_flow_id);
                let current_flow_id = if is_fwd { flow_id } else { reverse_flow_id };
                let now = Instant::now();
                let tcp_header_len = (tcp.get_data_offset() * 4) as u64;
                let total_header_len = ip_header_len + tcp_header_len;

                let flow = state.active_flows.entry(current_flow_id).or_insert_with(|| {
                    if is_fwd {
                        let history = state.host_history.entry(src_ip).or_default();
                        history.push_front((now, dst_port));
                        history.retain(|(t, _)| now.duration_since(*t).as_secs() < 60);
                    }
                    Flow {
                        src_ip, dst_ip, src_port, dst_port, protocol: "tcp".to_string(),
                        fwd_packet_count: 0, bwd_packet_count: 0,
                        fwd_total_bytes: 0, bwd_total_bytes: 0,
                        fwd_header_bytes: 0, bwd_header_bytes: 0,
                        fwd_packet_lengths: Vec::new(), bwd_packet_lengths: Vec::new(),
                        fwd_iat: Vec::new(), bwd_iat: Vec::new(),
                        start_time: now, last_seen: now, fwd_last_seen: now, bwd_last_seen: now,
                        fin_flag_count: 0, syn_flag_count: 0, rst_flag_count: 0,
                        psh_flag_count: 0, ack_flag_count: 0, urg_flag_count: 0,
                        ece_flag_count: 0,
                        init_fwd_win_bytes: None, init_bwd_win_bytes: None,
                        alerted: false,
                    }
                });

                flow.last_seen = now;
                if is_fwd {
                    if flow.fwd_packet_count > 0 {
                        flow.fwd_iat.push(now.duration_since(flow.fwd_last_seen).as_micros());
                    } else {
                        flow.init_fwd_win_bytes = Some(tcp.get_window());
                    }
                    flow.fwd_packet_count += 1;
                    flow.fwd_total_bytes += packet_size;
                    flow.fwd_header_bytes += total_header_len;
                    flow.fwd_packet_lengths.push(packet_size);
                    flow.fwd_last_seen = now;
                } else {
                    if flow.bwd_packet_count > 0 {
                        flow.bwd_iat.push(now.duration_since(flow.bwd_last_seen).as_micros());
                    } else {
                        flow.init_bwd_win_bytes = Some(tcp.get_window());
                    }
                    flow.bwd_packet_count += 1;
                    flow.bwd_total_bytes += packet_size;
                    flow.bwd_header_bytes += total_header_len;
                    flow.bwd_packet_lengths.push(packet_size);
                    flow.bwd_last_seen = now;
                }

                let flags = tcp.get_flags();
                if (flags & TcpFlags::FIN) != 0 { flow.fin_flag_count += 1; }
                if (flags & TcpFlags::SYN) != 0 { flow.syn_flag_count += 1; }
                if (flags & TcpFlags::RST) != 0 { flow.rst_flag_count += 1; }
                if (flags & TcpFlags::PSH) != 0 { flow.psh_flag_count += 1; }
                if (flags & TcpFlags::ACK) != 0 { flow.ack_flag_count += 1; }
                if (flags & TcpFlags::URG) != 0 { flow.urg_flag_count += 1; }
                if (flags & TcpFlags::ECE) != 0 { flow.ece_flag_count += 1; }
            }
        }
        17 => { // UDP
            if let Some(udp) = UdpPacket::new(payload) {
                let src_port = udp.get_source();
                let dst_port = udp.get_destination();
                let flow_id = (src_ip, dst_ip, src_port, dst_port, "udp".to_string());
                let now = Instant::now();
                let total_header_len = ip_header_len + 8;

                let flow = state.active_flows.entry(flow_id).or_insert_with(|| {
                    let history = state.host_history.entry(src_ip).or_default();
                    history.push_front((now, dst_port));
                    history.retain(|(t, _)| now.duration_since(*t).as_secs() < 60);
                    
                    Flow {
                        src_ip, dst_ip, src_port, dst_port, protocol: "udp".to_string(),
                        fwd_packet_count: 0, bwd_packet_count: 0,
                        fwd_total_bytes: 0, bwd_total_bytes: 0,
                        fwd_header_bytes: 0, bwd_header_bytes: 0,
                        fwd_packet_lengths: Vec::new(), bwd_packet_lengths: Vec::new(),
                        fwd_iat: Vec::new(), bwd_iat: Vec::new(),
                        start_time: now, last_seen: now, fwd_last_seen: now, bwd_last_seen: now,
                        fin_flag_count: 0, syn_flag_count: 0, rst_flag_count: 0,
                        psh_flag_count: 0, ack_flag_count: 0, urg_flag_count: 0,
                        ece_flag_count: 0,
                        init_fwd_win_bytes: None, init_bwd_win_bytes: None,
                        alerted: false,
                    }
                });
                
                flow.last_seen = now;
                if flow.fwd_packet_count > 0 {
                    flow.fwd_iat.push(now.duration_since(flow.fwd_last_seen).as_micros());
                }
                flow.fwd_packet_count += 1;
                flow.fwd_total_bytes += packet_size;
                flow.fwd_header_bytes += total_header_len;
                flow.fwd_packet_lengths.push(packet_size);
                flow.fwd_last_seen = now;
            }
        }
        _ => {}
    }
}

pub fn build_feature_vector(flow: &Flow) -> CicFeatureVector {
    let fwd_len_stats = calculate_stats_u64(&flow.fwd_packet_lengths);
    let bwd_len_stats = calculate_stats_u64(&flow.bwd_packet_lengths);
    let fwd_iat_stats = calculate_stats_u128(&flow.fwd_iat);
    let bwd_iat_stats = calculate_stats_u128(&flow.bwd_iat);
    let all_iat: Vec<u128> = flow.fwd_iat.iter().chain(flow.bwd_iat.iter()).cloned().collect();
    let flow_iat_stats = calculate_stats_u128(&all_iat);

    CicFeatureVector {
        dst_port: flow.dst_port,
        protocol: flow.protocol.clone(),
        flow_duration: flow.last_seen.duration_since(flow.start_time).as_micros(),
        total_fwd_packets: flow.fwd_packet_count,
        total_bwd_packets: flow.bwd_packet_count,
        total_len_fwd_packets: flow.fwd_total_bytes,
        total_len_bwd_packets: flow.bwd_total_bytes,
        fwd_packet_len_max: fwd_len_stats.max,
        fwd_packet_len_min: fwd_len_stats.min,
        fwd_packet_len_mean: fwd_len_stats.mean,
        fwd_packet_len_std: fwd_len_stats.std,
        bwd_packet_len_max: bwd_len_stats.max,
        bwd_packet_len_min: bwd_len_stats.min,
        bwd_packet_len_mean: bwd_len_stats.mean,
        bwd_packet_len_std: bwd_len_stats.std,
        flow_iat_mean: flow_iat_stats.mean,
        flow_iat_std: flow_iat_stats.std,
        flow_iat_max: flow_iat_stats.max,
        flow_iat_min: flow_iat_stats.min,
        fwd_iat_mean: fwd_iat_stats.mean,
        fwd_iat_max: fwd_iat_stats.max,
        bwd_iat_mean: bwd_iat_stats.mean,
        fwd_header_len: flow.fwd_header_bytes,
        fin_flag_count: flow.fin_flag_count,
        syn_flag_count: flow.syn_flag_count,
        rst_flag_count: flow.rst_flag_count,
        psh_flag_count: flow.psh_flag_count,
        ack_flag_count: flow.ack_flag_count,
        urg_flag_count: flow.urg_flag_count,
        ece_flag_count: flow.ece_flag_count,
        init_win_bytes_forward: flow.init_fwd_win_bytes.unwrap_or(0),
        init_win_bytes_backward: flow.init_bwd_win_bytes.unwrap_or(0),
    }
}

#[derive(Debug, Default)]
struct Stats { min: f64, max: f64, mean: f64, std: f64 }

fn calculate_stats_u64(data: &[u64]) -> Stats {
    if data.is_empty() { return Stats::default(); }
    let count = data.len() as f64;
    let sum = data.iter().sum::<u64>() as f64;
    let mean = sum / count;
    let variance = data.iter().map(|v| ((*v as f64) - mean).powi(2)).sum::<f64>() / count;
    Stats {
        min: *data.iter().min().unwrap_or(&0) as f64,
        max: *data.iter().max().unwrap_or(&0) as f64,
        mean,
        std: variance.sqrt(),
    }
}

fn calculate_stats_u128(data: &[u128]) -> Stats {
    if data.is_empty() { return Stats::default(); }
    let count = data.len() as f64;
    let sum = data.iter().sum::<u128>() as f64;
    let mean = sum / count;
    let variance = data.iter().map(|v| ((*v as f64) - mean).powi(2)).sum::<f64>() / count;
    Stats {
        min: *data.iter().min().unwrap_or(&0) as f64,
        max: *data.iter().max().unwrap_or(&0) as f64,
        mean,
        std: variance.sqrt(),
    }
}