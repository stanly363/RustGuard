use crate::{scanner, scanner::DeviceInfo};
use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

#[derive(Clone, Serialize, Debug)]
pub struct Alert {
    pub timestamp: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: String,
    pub attack_type: String,
}

#[derive(Clone)]
pub struct AppState {
    pub device_info: Arc<Mutex<HashMap<IpAddr, DeviceInfo>>>,
    pub alerts: Arc<Mutex<VecDeque<Alert>>>,
    pub interface_name: String,
}

pub async fn run_server(state: AppState) {
    let cors = CorsLayer::new().allow_origin(Any);

    let app = Router::new()
        .route("/api/devices", get(get_devices_handler))
        .route("/api/alerts", get(get_alerts_handler))
        .route("/api/scan/:ip", get(scan_ip_handler))
        .nest_service("/", ServeDir::new("static"))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("🌐 Web GUI available at http://127.0.0.1:3000/");
    axum::serve(listener, app).await.unwrap();
}

async fn get_devices_handler(State(state): State<AppState>) -> Json<HashMap<IpAddr, DeviceInfo>> {
    let devices_map = state.device_info.lock().unwrap();
    Json(devices_map.clone())
}

async fn get_alerts_handler(State(state): State<AppState>) -> Json<Vec<Alert>> {
    let alerts_deque = state.alerts.lock().unwrap();
    let alerts_vec: Vec<Alert> = alerts_deque.iter().cloned().collect();
    Json(alerts_vec)
}

async fn scan_ip_handler(
    State(state): State<AppState>,
    Path(ip_str): Path<String>,
) -> Json<DeviceInfo> {
    let ip: IpAddr = ip_str.parse().expect("Invalid IP address format");
    let interface_name = state.interface_name.clone();

    let old_device_info = {
        let devices_map = state.device_info.lock().unwrap();
        devices_map.get(&ip).cloned()
    };

    let mut fresh_device_info = scanner::scan_ip(ip, &interface_name).await;

    if let Some(old_info) = old_device_info {
        if old_info.mac_address.is_some() {
            fresh_device_info.mac_address = old_info.mac_address;
        }
        if fresh_device_info.hostname.is_none() && old_info.hostname.is_some() {
            fresh_device_info.hostname = old_info.hostname;
        }
        if let (Some(fresh_ports), Some(old_ports)) = (&fresh_device_info.open_ports, &old_info.open_ports) {
            if fresh_ports.is_empty() && !old_ports.is_empty() {
                fresh_device_info.open_ports = Some(old_ports.clone());
            }
        }
    }

    {
        let mut devices_map = state.device_info.lock().unwrap();
        fresh_device_info.is_scanning = false; 
        devices_map.insert(ip, fresh_device_info.clone());
    }

    Json(fresh_device_info)
}