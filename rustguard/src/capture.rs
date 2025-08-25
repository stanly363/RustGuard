use pcap::{Capture, Device, Error as PcapError};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use colored::*;
use ipnetwork::IpNetwork;
use crate::ai::AnomalyDetector;
use crate::python_diagnoser::PythonDiagnoser;
use crate::web::{Alert, AppState};
use crate::model::{build_feature_vector, handle_packet};
use crate::state::NetworkState;
use crate::scanner;
use chrono::Utc;
use std::collections::HashSet;

pub fn list_devices() -> Result<Vec<Device>, PcapError> {
    Device::list()
}

fn is_local_ip(ip: IpAddr, local_networks: &[IpNetwork]) -> bool {
    local_networks.iter().any(|net| net.contains(ip))
}

pub fn start_training_capture(
    interface_name: &str,
    duration_secs: u64,
    state: AppState,
    local_networks: Vec<IpNetwork>,
) -> Result<Vec<crate::state::CicFeatureVector>, Box<dyn std::error::Error>> {
    let selected_device = Device::list()?.into_iter().find(|d| d.name == interface_name).ok_or("Device not found")?;
    let mut cap = Capture::from_device(selected_device)?.promisc(true).timeout(1000).open()?;
    let mut network_state = NetworkState::new();
    let flow_timeout = Duration::from_secs(30);
    let training_duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    let mut collected_vectors = Vec::new();

    while start_time.elapsed() < training_duration {
        if let Ok(packet) = cap.next_packet() {
            handle_packet(packet.data, &mut network_state, None);
        }

        let now = Instant::now();
        let mut completed_flows = Vec::new();
        let mut flows_to_remove = Vec::new();

        for (key, flow) in network_state.active_flows.iter() {
            if now.duration_since(flow.last_seen) > flow_timeout {
                collected_vectors.push(build_feature_vector(flow));
                completed_flows.push(flow.clone());
                flows_to_remove.push(key.clone());
            }
        }
        
        if !completed_flows.is_empty() {
            let mut devices = state.device_info.lock().unwrap();
            for flow in &completed_flows {
                 for ip in [flow.src_ip, flow.dst_ip] {
                    if is_local_ip(ip, &local_networks) && !devices.contains_key(&ip) {
                        devices.insert(ip, scanner::DeviceInfo::new_scanning(ip));
                        let state_clone = state.clone();
                        let if_name_clone = state.interface_name.clone();
                        tokio::spawn(async move {
                            let info = scanner::scan_ip(ip, &if_name_clone).await;
                            let mut devices_map = state_clone.device_info.lock().unwrap();
                            devices_map.insert(ip, info);
                        });
                    }
                }
            }
        }

        for key in flows_to_remove {
            network_state.active_flows.remove(&key);
        }
    }

    Ok(collected_vectors)
}

pub fn start_detection_capture(
    interface_name: &str,
    detector: AnomalyDetector,
    diagnoser: PythonDiagnoser,
    state: AppState,
    local_networks: Vec<IpNetwork>,
    local_ip_to_ignore: Option<IpAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let selected_device = Device::list()?.into_iter().find(|d| d.name == interface_name).ok_or("Device not found")?;
    let mut cap = Capture::from_device(selected_device)?.promisc(true).timeout(1000).open()?;
    let mut network_state = NetworkState::new();
    let flow_timeout = Duration::from_secs(30);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    let mut last_active_check = Instant::now();
    let active_check_interval = Duration::from_secs(5);

    loop {
        if !running.load(Ordering::SeqCst) {
            println!("\nShutting down gracefully...");
            break Ok(());
        }
        if let Ok(packet) = cap.next_packet() {
            handle_packet(packet.data, &mut network_state, local_ip_to_ignore);
        }

        let now = Instant::now();

        let mut completed_flows = Vec::new();
        let mut flows_to_remove = Vec::new();
        for (key, flow) in &network_state.active_flows {
            let is_timed_out = now.duration_since(flow.last_seen) > flow_timeout;
            let is_tcp_closed = flow.protocol == "tcp" && (flow.fin_flag_count > 0 || flow.rst_flag_count > 0);
            if is_timed_out || is_tcp_closed {
                completed_flows.push(flow.clone());
                flows_to_remove.push(key.clone());
            }
        }

        if !completed_flows.is_empty() {
            let mut devices = state.device_info.lock().unwrap();
            for flow in &completed_flows {
                 for ip in [flow.src_ip, flow.dst_ip] {
                    if is_local_ip(ip, &local_networks) {
                        if !devices.contains_key(&ip) {
                            println!("Discovered new local device: {}", ip);
                            devices.insert(ip, scanner::DeviceInfo::new_scanning(ip));
                            let state_clone = state.clone();
                            let if_name_clone = state.interface_name.clone();
                            tokio::spawn(async move {
                                let info = scanner::scan_ip(ip, &if_name_clone).await;
                                let mut devices_map = state_clone.device_info.lock().unwrap();
                                devices_map.insert(ip, info);
                            });
                        }
                    }
                }
            }
        }

        for key in flows_to_remove {
            network_state.active_flows.remove(&key);
        }

        for flow in completed_flows {
            let feature_vector = build_feature_vector(&flow);
            if detector.is_anomalous(&feature_vector) {
                println!("{}", "!!! ANOMALY DETECTED (Completed Flow) !!!".red().bold());
                println!("Flow: {}:{} -> {}:{}", flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port);
                println!("Passing to Python for detailed diagnosis...");
                match diagnoser.diagnose(&feature_vector) {
                    Ok(diagnosis) => {
                        if diagnosis != "Benign" {
                            println!("{} {}", "Python Diagnosis:".yellow().bold(), diagnosis.yellow().bold());
                            let alert = Alert {
                                timestamp: Utc::now(),
                                src_ip: flow.src_ip,
                                src_port: flow.src_port,
                                dst_ip: flow.dst_ip,
                                dst_port: flow.dst_port,
                                protocol: flow.protocol.clone(),
                                attack_type: diagnosis,
                            };
                            let mut alerts = state.alerts.lock().unwrap();
                            alerts.push_front(alert);
                            alerts.truncate(50);
                        } else {
                            println!("{}", "Python Diagnosis: Anomaly was likely benign.".italic());
                        }
                    },
                    Err(e) => eprintln!("Error during Python diagnosis: {}", e),
                }
                println!("---------------------------------");
            }
        }

        if now.duration_since(last_active_check) > active_check_interval {
            println!("[Active Flow Check] Analyzing {} active flows...", network_state.active_flows.len());
            let active_flow_keys: Vec<_> = network_state.active_flows.keys().cloned().collect();

            for key in active_flow_keys {
                if let Some(flow) = network_state.active_flows.get_mut(&key) {
                    if !flow.alerted {
                        let feature_vector = build_feature_vector(flow);
                        if detector.is_anomalous(&feature_vector) {
                            flow.alerted = true;
                            
                            println!("{}", "!!! ANOMALY DETECTED (Active Flow) !!!".magenta().bold());
                            println!("Flow: {}:{} -> {}:{}", flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port);
                            println!("Passing to Python for detailed diagnosis...");
                            match diagnoser.diagnose(&feature_vector) {
                                Ok(diagnosis) => {
                                    if diagnosis != "Benign" {
                                        println!("{} {}", "Python Diagnosis:".yellow().bold(), diagnosis.yellow().bold());
                                        let alert = Alert {
                                            timestamp: Utc::now(),
                                            src_ip: flow.src_ip,
                                            src_port: flow.src_port,
                                            dst_ip: flow.dst_ip,
                                            dst_port: flow.dst_port,
                                            protocol: flow.protocol.clone(),
                                            attack_type: diagnosis,
                                        };
                                        let mut alerts = state.alerts.lock().unwrap();
                                        alerts.push_front(alert);
                                        alerts.truncate(50);
                                    } else {
                                        println!("{}", "Python Diagnosis: Anomaly was likely benign.".italic());
                                    }
                                },
                                Err(e) => eprintln!("Error during Python diagnosis: {}", e),
                            }
                            println!("---------------------------------");
                        }
                    }
                }
            }

            // STAGE 3: PERIODICALLY ANALYZE HOST BEHAVIOR
            const PORT_SCAN_THRESHOLD: usize = 15;
            
            let mut port_scanners = Vec::new();
            for (ip, history) in &network_state.host_history {
                let unique_ports: HashSet<u16> = history.iter().map(|(_, port)| *port).collect();
                if unique_ports.len() > PORT_SCAN_THRESHOLD {
                    port_scanners.push(*ip);
                }
            }
            
            for ip in port_scanners {
                println!("{}", format!("!!! HOST-BASED ALERT: Port Scan detected from {} !!!", ip).red().bold());
                let alert = Alert {
                    timestamp: Utc::now(),
                    src_ip: ip,
                    src_port: 0,
                    dst_ip: "0.0.0.0".parse().unwrap(),
                    dst_port: 0,
                    protocol: "N/A".to_string(),
                    attack_type: "Port Scan".to_string(),
                };
                let mut alerts = state.alerts.lock().unwrap();
                alerts.push_front(alert);
                alerts.truncate(50);
                
                network_state.host_history.remove(&ip);
            }
            
            last_active_check = now;
        }
    }
}