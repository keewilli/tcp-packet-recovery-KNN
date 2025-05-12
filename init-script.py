#!/usr/bin/env python3
"""
init_project.py - Initialize the TCP Packet Recovery project structure

This script creates the necessary directory structure and empty files
for the TCP Packet Recovery project.
"""

import os
import sys
import shutil
import argparse

def create_directory(directory):
    """Create a directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")
    else:
        print(f"Directory already exists: {directory}")

def create_empty_file(file_path):
    """Create an empty file if it doesn't exist."""
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            f.write("")
        print(f"Created empty file: {file_path}")
    else:
        print(f"File already exists: {file_path}")

def create_init_file(directory):
    """Create an __init__.py file in a directory."""
    init_file = os.path.join(directory, "__init__.py")
    if not os.path.exists(init_file):
        with open(init_file, 'w') as f:
            f.write('"""TCP Packet Recovery module."""\n\n')
            f.write('from .packet_monitor import PacketMonitor\n')
            f.write('from .packet_capture import PacketCapture\n')
            f.write('from .packet_analyzer import PacketAnalyzer\n')
            f.write('from .knn_model import KNNModel\n')
            f.write('from .packet_injector import PacketInjector\n')
            f.write('from .event_logger import EventLogger\n')
            f.write('from .visualizer import PacketVisualizer\n\n')
            f.write('__all__ = [\n')
            f.write('    "PacketMonitor",\n')
            f.write('    "PacketCapture",\n')
            f.write('    "PacketAnalyzer",\n')
            f.write('    "KNNModel",\n')
            f.write('    "PacketInjector",\n')
            f.write('    "EventLogger",\n')
            f.write('    "PacketVisualizer",\n')
            f.write(']\n')
        print(f"Created __init__.py file: {init_file}")
    else:
        print(f"__init__.py file already exists: {init_file}")

def create_project_structure(root_dir):
    """Create the project directory structure."""
    # Create main directories
    create_directory(os.path.join(root_dir, "src"))
    create_directory(os.path.join(root_dir, "src", "tcp_packet_recovery"))
    create_directory(os.path.join(root_dir, "config"))
    create_directory(os.path.join(root_dir, "scripts"))
    create_directory(os.path.join(root_dir, "examples"))
    create_directory(os.path.join(root_dir, "tests"))
    create_directory(os.path.join(root_dir, "tests", "test_data"))
    create_directory(os.path.join(root_dir, "docs"))
    
    # Create __init__.py files
    create_init_file(os.path.join(root_dir, "src", "tcp_packet_recovery"))
    create_init_file(os.path.join(root_dir, "tests"))
    
    # Create empty module files
    module_files = [
        "packet_capture.py",
        "packet_analyzer.py",
        "knn_model.py",
        "packet_injector.py",
        "event_logger.py",
        "visualizer.py",
        "packet_monitor.py",
    ]
    
    for module_file in module_files:
        create_empty_file(os.path.join(root_dir, "src", "tcp_packet_recovery", module_file))
    
    # Create test files
    test_files = [
        "test_packet_capture.py",
        "test_packet_analyzer.py",
        "test_knn_model.py",
        "test_packet_injector.py",
        "test_event_logger.py",
        "test_visualizer.py",
        "test_packet_monitor.py",
    ]
    
    for test_file in test_files:
        create_empty_file(os.path.join(root_dir, "tests", test_file))
    
    # Create documentation files
    doc_files = [
        "installation.md",
        "usage.md",
        "api.md",
    ]
    
    for doc_file in doc_files:
        create_empty_file(os.path.join(root_dir, "docs", doc_file))
    
    # Create config file
    config_file = os.path.join(root_dir, "config", "config.ini")
    with open(config_file, 'w') as f:
        f.write("[capture]\n")
        f.write("interface = \n")
        f.write("filter = tcp\n")
        f.write("buffer_size = 1000\n\n")
        f.write("[knn]\n")
        f.write("n_neighbors = 5\n")
        f.write("weights = distance\n")
        f.write("model_path = \n\n")
        f.write("[injection]\n")
        f.write("confidence_threshold = 0.7\n\n")
        f.write("[database]\n")
        f.write("url = sqlite:///packet_events.db\n")
        f.write("auto_flush_interval = 5.0\n\n")
        f.write("[visualization]\n")
        f.write("enabled = true\n")
        f.write("host = 127.0.0.1\n")
        f.write("port = 8050\n")
        f.write("update_interval = 1.0\n\n")
        f.write("[logging]\n")
        f.write("level = INFO\n")
        f.write("file = \n")
    print(f"Created config file: {config_file}")
    
    # Create README.md
    readme_file = os.path.join(root_dir, "README.md")
    if not os.path.exists(readme_file):
        with open(readme_file, 'w') as f:
            f.write("# TCP Packet Recovery Using KNN\n\n")
            f.write("A Python framework for detecting, logging, and recovering missing packets in TCP connection streams using the K-Nearest Neighbors machine learning algorithm.\n\n")
            f.write("## Installation\n\n")
            f.write("```bash\n")
            f.write("# Clone the repository\n")
            f.write("git clone https://github.com/yourusername/tcp-packet-recovery.git\n")
            f.write("cd tcp-packet-recovery\n\n")
            f.write("# Install dependencies\n")
            f.write("pip install -r requirements.txt\n\n")
            f.write("# Install the package in development mode\n")
            f.write("pip install -e .\n")
            f.write("```\n\n")
            f.write("## Usage\n\n")
            f.write("See the `examples` directory for usage examples.\n\n")
            f.write("## License\n\n")
            f.write("This project is licensed under the MIT License - see the LICENSE file for details.\n")
        print(f"Created README.md file: {readme_file}")
    else:
        print(f"README.md file already exists: {readme_file}")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Initialize TCP Packet Recovery project structure')
    parser.add_argument('-d', '--directory', default='.', help='Root directory for the project')
    
    args = parser.parse_args()
    
    create_project_structure(args.directory)
    print("Project structure initialized successfully!")

if __name__ == '__main__':
    main()
