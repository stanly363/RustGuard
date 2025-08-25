use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use colored::*;
use ipnetwork::IpNetwork;
use pnet::datalink;
use crate::ai::AnomalyDetector;
use crate::python_diagnoser::PythonDiagnoser;
use crate::web::AppState;

mod state;
mod model;
mod capture;
mod ai;
mod python_diagnoser;
mod web;
mod scanner;

#[tokio::main]
async fn main() {
    let devices = match capture::list_devices() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to list devices: {}", e);
            return;
        }
    };

    if devices.is_empty() {
        eprintln!("No network capture devices found.");
        return;
    }

    println!("Available network devices:");
    for (i, device) in devices.iter().enumerate() {
        println!("[{}] {} ({})", i, device.name, device.desc.as_deref().unwrap_or("No description"));
    }

    print!("\nPlease enter the number of the device you want to capture on: ");
    io::stdout().flush().unwrap();
    let mut choice_str = String::new();
    io::stdin().read_line(&mut choice_str).expect("Failed to read your choice");
    let choice_index: usize = match choice_str.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            eprintln!("Invalid input. Please enter a number.");
            return;
        }
    };
    let chosen_device = match devices.get(choice_index) {
        Some(d) => d,
        None => {
            eprintln!("Invalid device number selected.");
            return;
        }
    };
    let interface_name = chosen_device.name.clone();

    let all_interfaces = datalink::interfaces();
    let local_networks: Vec<IpNetwork> = all_interfaces
        .iter()
        .find(|iface| iface.name == interface_name)
        .map(|iface| iface.ips.clone())
        .unwrap_or_else(Vec::new);

    let local_ip_to_ignore: Option<IpAddr> = all_interfaces
        .iter()
        .find(|iface| iface.name == interface_name)
        .and_then(|iface| {
            iface.ips.iter()
                .find(|ip_net| ip_net.is_ipv4())
                .map(|ip_net| ip_net.ip())
        });

    if let Some(ip) = local_ip_to_ignore {
        println!("Ignoring outbound traffic from local IP: {}", ip.to_string().yellow());
    }

    print!("Run in training mode (to build anomaly detection baseline)? (y/n): ");
    io::stdout().flush().unwrap();
    let mut mode_choice_str = String::new();
    io::stdin().read_line(&mut mode_choice_str).expect("Failed to read mode choice");
    let is_training_mode = mode_choice_str.trim().eq_ignore_ascii_case("y");

    let shared_state = AppState {
        device_info: Arc::new(Mutex::new(HashMap::new())),
        alerts: Arc::new(Mutex::new(VecDeque::new())),
        interface_name: interface_name.clone(),
    };

    let web_state = shared_state.clone();
    tokio::spawn(async move {
        web::run_server(web_state).await;
    });

    let periodic_scan_state = shared_state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        println!("Periodic 10-minute network scan is active.");
        loop {
            interval.tick().await;
            println!("\nStarting periodic 10-minute network scan...");
            let (ips_to_scan, if_name): (Vec<IpAddr>, String) = {
                let state_lock = periodic_scan_state.device_info.lock().unwrap();
                (
                    state_lock.keys().cloned().collect(),
                    periodic_scan_state.interface_name.clone(),
                )
            };

            if !ips_to_scan.is_empty() {
                println!("Periodic rescan tasks launched for {} device(s).", ips_to_scan.len());
                for ip in ips_to_scan {
                    let state_clone = periodic_scan_state.clone();
                    let if_name_clone = if_name.clone();
                    tokio::spawn(async move {
                        let old_info = {
                            let devices_map = state_clone.device_info.lock().unwrap();
                            devices_map.get(&ip).cloned()
                        };

                        let mut fresh_info = scanner::scan_ip(ip, &if_name_clone).await;

                        if let Some(old) = old_info {
                            if old.mac_address.is_some() {
                                fresh_info.mac_address = old.mac_address;
                            }
                            if fresh_info.hostname.is_none() && old.hostname.is_some() {
                                fresh_info.hostname = old.hostname;
                            }
                            if let (Some(fresh_ports), Some(old_ports)) = (&fresh_info.open_ports, &old.open_ports) {
                                if fresh_ports.is_empty() && !old_ports.is_empty() {
                                    fresh_info.open_ports = Some(old_ports.clone());
                                }
                            }
                        }
                        
                        let mut devices_map = state_clone.device_info.lock().unwrap();
                        fresh_info.is_scanning = false;
                        devices_map.insert(ip, fresh_info);
                    });
                }
            } else {
                println!("No local devices discovered yet, skipping periodic scan.");
            }
        }
    });

    tokio::task::spawn_blocking(move || {
        if is_training_mode {
            let duration = 300;
            println!("\n{}", "Starting in Training Mode...".yellow());
            println!("Capturing traffic on '{}' for {} seconds to build a behavioral baseline.", interface_name, duration);
            match capture::start_training_capture(&interface_name, duration, shared_state, local_networks) {
                Ok(feature_vectors) => {
                    if feature_vectors.is_empty() {
                        println!("{}", "No network flows completed during training. Try a longer duration.".red());
                    } else {
                        println!("Captured {} network flows. Training anomaly detection model...", feature_vectors.len());
                        ai::train_model(feature_vectors);
                        println!("{}", "Anomaly detection model training complete. Model saved to 'model.json'.".green());
                        println!("You can now run in detection mode.");
                    }
                },
                Err(e) => eprintln!("An error occurred during training: {}", e),
            }
        } else {
            println!("\n{}", "Starting in Detection Mode...".blue());
            match AnomalyDetector::new("model.json") {
                Ok(detector) => {
                    println!("{}", "✅ Stage 1 (Rust Anomaly Detector) loaded successfully.".green());
                    match PythonDiagnoser::new() {
                        Ok(diagnoser) => {
                            println!("{}", "✅ Stage 2 (Python Specialist Diagnoser) loaded successfully.".green());
                            println!("Monitoring for anomalous network behavior on '{}'...", interface_name);
                            if let Err(e) = capture::start_detection_capture(&interface_name, detector, diagnoser, shared_state, local_networks, local_ip_to_ignore) {
                                eprintln!("Application error: {}", e);
                            }
                        },
                        Err(e) => eprintln!("❌ Error loading Python diagnoser: {}", e),
                    }
                },
                Err(_) => eprintln!("{}", "❌ Error: Could not load 'model.json'. Please run in training mode first.".red()),
            }
        }
    }).await.unwrap();
}