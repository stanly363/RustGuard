use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Instant;
use ndarray::Array1;

#[derive(Debug, Clone)]
pub struct Flow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub fwd_packet_count: u64,
    pub bwd_packet_count: u64,
    pub fwd_total_bytes: u64,
    pub bwd_total_bytes: u64,
    pub fwd_header_bytes: u64,
    pub bwd_header_bytes: u64,
    pub fwd_packet_lengths: Vec<u64>,
    pub bwd_packet_lengths: Vec<u64>,
    pub fwd_iat: Vec<u128>,
    pub bwd_iat: Vec<u128>,
    pub start_time: Instant,
    pub last_seen: Instant,
    pub fwd_last_seen: Instant,
    pub bwd_last_seen: Instant,
    pub fin_flag_count: u32,
    pub syn_flag_count: u32,
    pub rst_flag_count: u32,
    pub psh_flag_count: u32,
    pub ack_flag_count: u32,
    pub urg_flag_count: u32,
    pub ece_flag_count: u32,
    pub init_fwd_win_bytes: Option<u16>,
    pub init_bwd_win_bytes: Option<u16>,
    pub alerted: bool,
}

#[derive(Debug)]
pub struct CicFeatureVector {
    pub dst_port: u16,
    pub protocol: String,
    pub flow_duration: u128,
    pub total_fwd_packets: u64,
    pub total_bwd_packets: u64,
    pub total_len_fwd_packets: u64,
    pub total_len_bwd_packets: u64,
    pub fwd_packet_len_max: f64,
    pub fwd_packet_len_min: f64,
    pub fwd_packet_len_mean: f64,
    pub fwd_packet_len_std: f64,
    pub bwd_packet_len_max: f64,
    pub bwd_packet_len_min: f64,
    pub bwd_packet_len_mean: f64,
    pub bwd_packet_len_std: f64,
    pub flow_iat_mean: f64,
    pub flow_iat_std: f64,
    pub flow_iat_max: f64,
    pub flow_iat_min: f64,
    pub fwd_iat_mean: f64,
    pub fwd_iat_max: f64,
    pub bwd_iat_mean: f64,
    pub fwd_header_len: u64,
    pub fin_flag_count: u32,
    pub syn_flag_count: u32,
    pub rst_flag_count: u32,
    pub psh_flag_count: u32,
    pub ack_flag_count: u32,
    pub urg_flag_count: u32,
    pub ece_flag_count: u32,
    pub init_win_bytes_forward: u16,
    pub init_win_bytes_backward: u16,
}

impl CicFeatureVector {
    pub fn to_ndarray(&self) -> Array1<f64> {
        Array1::from(vec![
            self.flow_duration as f64,
            self.total_fwd_packets as f64,
            self.total_bwd_packets as f64,
            self.total_len_fwd_packets as f64,
            self.total_len_bwd_packets as f64,
            self.fwd_packet_len_max,
            self.fwd_packet_len_min,
            self.fwd_packet_len_mean,
            self.fwd_packet_len_std,
            self.bwd_packet_len_max,
            self.bwd_packet_len_min,
            self.bwd_packet_len_mean,
            self.bwd_packet_len_std,
            self.flow_iat_mean,
            self.flow_iat_std,
            self.flow_iat_max,
            self.flow_iat_min,
            self.fwd_iat_mean,
            self.bwd_iat_mean,
            self.fin_flag_count as f64,
            self.syn_flag_count as f64,
            self.rst_flag_count as f64,
            self.psh_flag_count as f64,
            self.ack_flag_count as f64,
            self.urg_flag_count as f64,
        ])
    }
    
    pub fn to_diagnostic_ndarray(&self) -> Array1<f32> {
        Array1::from(vec![
            self.dst_port as f32,
            self.protocol_to_float(),
            self.flow_duration as f32,
            self.fwd_packet_len_max as f32,
            self.fwd_packet_len_std as f32,
            self.bwd_packet_len_max as f32,
            self.bwd_packet_len_mean as f32,
            self.bwd_packet_len_std as f32,
            self.flow_packets_per_second(),
            self.flow_iat_mean as f32,
            self.flow_iat_max as f32,
            self.flow_iat_min as f32,
            self.fwd_iat_mean as f32,
            self.fwd_iat_max as f32,  
            self.fwd_header_len as f32,  
            self.fwd_packets_per_second(),
            self.bwd_packets_per_second(),
            self.rst_flag_count as f32,
            self.psh_flag_count as f32,
            self.ack_flag_count as f32,
            self.urg_flag_count as f32,
            self.ece_flag_count as f32, 
            self.init_win_bytes_forward as f32,  
            self.init_win_bytes_backward as f32, 
            20.0,
        ])
    }

    fn protocol_to_float(&self) -> f32 {
        match self.protocol.as_str() { "tcp" => 6.0, "udp" => 17.0, _ => 0.0 }
    }
    fn flow_packets_per_second(&self) -> f32 {
        let duration_sec = self.flow_duration as f32 / 1_000_000.0;
        if duration_sec > 0.0 { (self.total_fwd_packets + self.total_bwd_packets) as f32 / duration_sec } else { 0.0 }
    }
    fn fwd_packets_per_second(&self) -> f32 {
        let duration_sec = self.flow_duration as f32 / 1_000_000.0;
        if duration_sec > 0.0 { self.total_fwd_packets as f32 / duration_sec } else { 0.0 }
    }
    fn bwd_packets_per_second(&self) -> f32 {
        let duration_sec = self.flow_duration as f32 / 1_000_000.0;
        if duration_sec > 0.0 { self.total_bwd_packets as f32 / duration_sec } else { 0.0 }
    }
}

pub type FlowId = (IpAddr, IpAddr, u16, u16, String);

pub struct NetworkState {
    pub active_flows: HashMap<FlowId, Flow>,
    pub host_history: HashMap<IpAddr, VecDeque<(Instant, u16)>>,
}

impl NetworkState {
    pub fn new() -> Self {
        NetworkState {
            active_flows: HashMap::new(),
            host_history: HashMap::new(),
        }
    }
}