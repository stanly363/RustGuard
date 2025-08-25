# RustGuard: A Two-Stage Hybrid Intrusion Detection System



RustGuard is a high-performance network Intrusion Detection System (IDS) that leverages the speed of Rust for real-time packet analysis and the power of Python's machine learning ecosystem for intelligent threat diagnosis. It uses a unique two-stage pipeline to efficiently filter traffic and provide detailed classifications of network attacks.







## Overview



The system operates by capturing network traffic directly from an interface. It first uses a lightweight, unsupervised anomaly detector written in Rust to flag statistically unusual network flows. These suspicious flows are then passed to a more sophisticated, supervised AI model in Python for an expert diagnosis, classifying them as either benign or a specific type of attack. The system also incorporates host-based behavioral analysis to detect attacks like port scans that are invisible to simple flow-based analysis.



## Features



- **Two-Stage ML Detection:** A fast Rust-based K-Means Anomaly Detector (Stage 1) filters traffic for a powerful Python-based Random Forest Classifier (Stage 2).

- **Host-Based Behavioral Analysis:** Tracks the activity of individual IPs over time to detect patterns like port scans that occur across multiple flows.

- **Real-time Packet Capture:** Uses `pcap` to capture and analyze network traffic live.

- **Automatic Device Discovery:** Discovers local devices on the network and performs active scans to gather information (Hostname, MAC, Open Ports).

- **Intelligent Rescanning:** Periodically rescans devices but preserves known information (like MAC addresses and port lists) to prevent data loss from temporary scan failures.

- **Web-Based Dashboard:** A user-friendly interface built with Axum to display discovered devices and real-time security alerts.

- **Self-Training Capability:** The system can be run in a training mode to build a baseline model of your network's normal behavior.



## How It Works: The Two-Stage Detection Pipeline



RustGuard's intelligence comes from its multi-layered approach to detection.



---

### ### Stage 1: Rust Anomaly Detector (The Fast Filter)



The first stage is an unsupervised K-Means clustering model written entirely in Rust (`src/ai.rs`).



- **Training:** When you run the application in "training mode," it captures all network flows for a set period and learns what "normal" traffic looks like by grouping similar flows into clusters. It establishes a statistical baseline for your specific network.

- **Detection:** In detection mode, this model acts as a high-speed filter. For every network flow, it calculates a feature vector and measures its distance to the nearest "normal" cluster. If a flow is too far from any known normal cluster, it's flagged as an **anomaly**.

- **Purpose:** This stage is designed for speed. It doesn't know *what* an attack is, only what is statistically *unusual*. Its job is to reduce the massive volume of network traffic down to a small, manageable stream of suspicious flows for the expert to analyze.



---

### ### Stage 2: Python Diagnoser (The Expert Analyst)



The flows flagged as anomalous by Stage 1 are passed to the expert AI in Python (`ml_analysis.py`). This stage uses two supervised Random Forest models.



1.  **The Gatekeeper Model:** This is a binary classifier trained to be an expert at one thing: distinguishing between "Benign" and "Attack". It provides the first real verdict on the anomalous flow.

2.  **The Specialist Model:** If the Gatekeeper identifies a flow as an "Attack", it is then passed to this multi-class classifier. The Specialist is trained on labeled examples of specific attacks (e.g., Port Scan, DDoS, Brute Force) and provides the final, detailed diagnosis.



- **Purpose:** This stage provides accuracy and detail. By using models trained on specific, labeled attack patterns, it can correctly identify the type of threat or dismiss an anomaly flagged by Stage 1 as ultimately benign, significantly reducing false positives.



---

### ### Host-Based Detection (The Behavior Analyst)



Flow-based analysis is powerful, but some attacks are designed to look like a series of normal, individual flows. A port scan, for example, is just one host opening many brief connections to different ports on a target.



- **Tracking:** RustGuard creates an in-memory history for each source IP it sees (`src/state.rs`). It logs the timestamp and destination port of every new connection.

- **Analysis:** Periodically (`src/capture.rs`), the system analyzes this history. If it detects that a single IP has connected to an abnormally high number of unique ports in a short time, it triggers a "Port Scan" alert.

- **Purpose:** This adds a crucial layer of stateful analysis, allowing the IDS to detect coordinated activities that are invisible when looking at each network flow in isolation.



## Getting Started



### Prerequisites



- **Rust:** Install via [rustup](https://rustup.rs/).

- **Python:** Version 3.8 or higher.

- **`pcap` library:** You may need to install development libraries for `libpcap` (Linux: `sudo apt-get install libpcap-dev`) or Npcap (Windows).



### Building the Project



1.  Clone the repository.

2.  Navigate to the project directory.

3.  Build the project in release mode for the best performance:



    cargo build --release




## How to Use RustGuard



Using the system is a three-step process: training the Rust Anomaly Detector, training the Python AI models, and finally running in detection mode.



---

### ### Step 1: Training the Anomaly Detector (Critical First Step)



This step creates the `model.json` file, which teaches the system what your network's normal traffic looks like.



1.  Run the application from your terminal: `cargo run --release`

2.  When prompted, choose to run in **training mode (y)**.

3.  Let the application run for the duration (e.g., 5 minutes) on your network during a period of normal activity. **Avoid running any attacks during this phase.**



---

### ### Step 2: Training the Python AI Models (The Core Brain)



This step creates the `.joblib` files that the Python expert analyst uses.



1.  **Collect Data:** Gather PCAP files of both benign and malicious traffic. Place them in `pcap_samples/benign` and `pcap_samples/malicious` respectively. For best results, use your own data (see the next section).

2.  **Extract Features:** Run the Python script to process the PCAPs into a feature set.

    ```bash

    python extract_features.py

    ```

    This creates `pcap_features.csv`.

3.  **(Optional) Balance Data:** Run the balancing scripts (`filter_attacks.py`, `balance_attacks.py`) to create a well-distributed malicious dataset.

4.  **Create Final Dataset:** Run `create_final_dataset.py` to combine your benign flows with your balanced malicious flows into `final_training_dataset.csv`.

5.  **Train Models:** Run the training script.

    ```bash

    python train_models.py

    ```

    This reads `final_training_dataset.csv` and generates all the required `.joblib` files (`gatekeeper_model.joblib`, `specialist_model.joblib`, etc.).



---

### ### Step 3: Running in Detection Mode



With `model.json` and all the `.joblib` files in place, you are ready to monitor your network.



1.  Run the application: `cargo run --release`

2.  Choose your network interface.

3.  When prompted, choose to run in **detection mode (n)**.

4.  Open `http://127.0.0.1:3000` in your browser to view the dashboard.



## Creating a High-Accuracy Model for Your Own Network



The most common cause of false positives or missed detections in any IDS is a mismatch between the training data and the real-world network it's protecting. To achieve the highest accuracy, you must train the AI on traffic from **your own network**.



### The Problem: Why Generic Datasets Fail



Every network has a unique "fingerprint." The services you use, the devices you own, and your daily habits create a pattern of traffic that is unique to you. A model trained on a generic university dataset will not understand the normal traffic patterns of a home network, and vice-versa.



### The Solution: A Personalized Training Workflow



Follow these steps to create a powerful, personalized model:



1.  **Capture High-Quality Benign Traffic:**

    - The goal is to create a large PCAP file that represents all your normal activities.

    - Use a tool like Wireshark or the `pcap` library to capture traffic on your main network interface for an extended period (several hours is good, a full day is even better).

    - During this capture, use your network as you normally would: browse the web, stream videos, work from home, play games, use chat apps, etc.

    - Save this capture and place it in your `pcap_samples/benign` folder.



2.  **Capture Malicious Traffic (Safely!):**

    - **WARNING:** Perform this step in an isolated, controlled environment. Use a virtual machine or a spare computer that is not connected to any important devices.

    - On this isolated network, run your detector on one machine (the target) and use another machine as the attacker.

    - For each attack you want to detect, start a capture, run the attack, stop the capture, and save the file with a descriptive name.

        - `nmap -sS <target_ip>` -> save as `PortScan.pcap`

        - `hping3 -S --flood -p 80 <target_ip>` -> save as `DDoS.pcap`

    - Place all these attack captures in your `pcap_samples/malicious` folder.



3.  **Follow the Training Pipeline:**

    - With your own high-quality `benign` and `malicious` PCAPs in place, follow **Step 2: Training the Python AI Models** from the section above.

    - Run `extract_features.py`, balance the data, create the final dataset, and finally run `train_models.py`.



The resulting `.joblib` files will be fine-tuned to the unique characteristics of your network, providing a significantly higher accuracy and a lower rate of false alarms.
