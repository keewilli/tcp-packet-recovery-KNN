#!/usr/bin/env python3
"""
setup.py - Installation script for the TCP Packet Recovery package
"""

from setuptools import setup, find_packages

setup(
    name="tcp-packet-recovery",
    version="0.1.0",
    description="TCP packet recovery using KNN",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/tcp-packet-recovery",
    packages=find_packages(),
    package_dir={"": "src"},
    install_requires=[
        "scapy>=2.4.5",
        "numpy>=1.20.0",
        "pandas>=1.3.0",
        "scikit-learn>=1.0.0",
        "matplotlib>=3.4.0",
        "dash>=2.0.0",
        "dash-bootstrap-components>=1.0.0",
        "plotly>=5.0.0",
        "sqlalchemy>=1.4.0",
        "psutil>=5.8.0",
    ],
    entry_points={
        "console_scripts": [
            "tcp-monitor=tcp_packet_recovery.packet_monitor:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
)
