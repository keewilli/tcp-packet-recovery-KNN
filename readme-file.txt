# TCP Packet Recovery Using KNN

A Python framework for detecting, logging, and recovering missing packets in TCP connection streams using the K-Nearest Neighbors (KNN) machine learning algorithm. This project provides a solution for real-time packet loss detection and recovery, with comprehensive logging and visualization capabilities.

## Features

- **Real-time TCP Stream Monitoring**: Capture and analyze TCP streams from network interfaces
- **KNN-based Packet Prediction**: Use machine learning to predict the content of missing packets
- **Packet Loss Detection**: Identify missing packets in TCP streams in real-time
- **Packet Injection**: Reconstruct and inject missing packets into the TCP stream
- **Event Logging**: Log packet-related events to a database for later analysis
- **Real-time Visualization**: Web-based dashboard for visualizing packet statistics

## Project Structure

```
tcp-packet-recovery/
├── src/
│   ├── tcp_packet_recovery/
│   │   ├── __init__.py
│   │   ├── packet_capture.py
│   │   ├── packet_analyzer.py
│   │   ├── knn_model.py
│   │   ├── packet_injector.py
│   │   ├── event_logger.py
│   │   ├── visualizer.py
│   │   └── packet_monitor.py
├── config/
│   └── config.ini
├── scripts/
│   ├── init_project.py
│   ├── run_monitor.py
│   └── train_model.py
├── examples/
│   ├── basic_monitoring.py
│   ├── advanced_recovery.py
│   └── custom_visualization.py
├── tests/
│   ├── test_packet_capture.py
│   ├── test_knn_model.py
│   └── ...
├── docs/
│   ├── installation.md
│   ├── usage.md
│   └── api.md
├── requirements.txt
├── setup.py
├── .gitignore
└── README.md
```

## Installation

### Prerequisites

- Python 3.8 or higher
- Administrative/root privileges (required for packet capture)
- Linux, macOS, or Windows with libpcap (Npcap on Windows)

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/yourusername/tcp-packet-recovery.git
cd tcp-packet-recovery

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

## Quick Start

### Basic Usage

```python
from tcp_packet_recovery import PacketMonitor

# Initialize the packet monitor
monitor = PacketMonitor(interface="eth0")

# Start monitoring with default settings
monitor.start()

# Stop monitoring
monitor.stop()
```

### Command-line Usage

```bash
# Run the monitor with default settings
python scripts/run_monitor.py

# Run with specific interface and visualization on port 8080
python scripts/run_monitor.py -i eth0 --viz-port 8080

# Run with custom configuration file
python scripts/run_monitor.py -c my_config.ini
```

### Configuration

The system can be configured through a configuration file or command-line arguments. See `config/config.ini` for available options.

## Examples

### Basic Monitoring

```bash
python examples/basic_monitoring.py -i eth0 -d 60
```

This example monitors TCP streams on the specified interface for 60 seconds, detecting missing packets and displaying statistics.

### Advanced Recovery

```bash
python examples/advanced_recovery.py -i eth0 -m trained_model.pkl
```

This example demonstrates packet recovery by injecting reconstructed packets using a pre-trained KNN model.

### Custom Visualization

```bash
python examples/custom_visualization.py -i eth0 -p 8080
```

This example shows how to create a custom visualization dashboard for TCP packet statistics.

## Technical Details

### KNN Algorithm for Packet Prediction

The system uses the K-Nearest Neighbors algorithm to predict the content of missing packets based on surrounding packets in the stream. The model is trained on observed packets and learns patterns in the packet data.

### Packet Injection Process

1. **Detection**: Missing packets are detected by analyzing sequence numbers in the TCP stream
2. **Prediction**: The KNN model predicts the content of the missing packet
3. **Confidence Check**: Prediction confidence is evaluated against a threshold
4. **Injection**: If confidence is sufficient, the reconstructed packet is injected into the network

### Visualization Dashboard

The web-based dashboard provides real-time visualization of:
- Packet loss rates over time
- Recovery rates
- Stream statistics
- Recent packet events

## Requirements

- scapy>=2.4.5
- numpy>=1.20.0
- pandas>=1.3.0
- scikit-learn>=1.0.0
- matplotlib>=3.4.0
- dash>=2.0.0
- dash-bootstrap-components>=1.0.0
- plotly>=5.0.0
- sqlalchemy>=1.4.0
- psutil>=5.8.0

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
