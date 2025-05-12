#!/usr/bin/env python3
"""
packet_capture.py - Module for capturing TCP packets and reconstructing streams

This module provides functionality to capture TCP packets from network interfaces
and reconstruct TCP streams for further analysis. It uses scapy for packet capture
and maintains a buffer of recent packets for each TCP connection.
"""

import time
import threading
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Callable

from scapy.all import sniff, IP, TCP, Raw
from scapy.sessions import TCPSession

class StreamBuffer:
    """Maintains a buffer of TCP packets for a specific stream."""
    
    def __init__(self, max_size: int = 1000):
        """
        Initialize a stream buffer.
        
        Args:
            max_size: Maximum number of packets to store in the buffer
        """
        self.packets = []
        self.max_size = max_size
        self.sequence_numbers = set()
        self.lock = threading.Lock()
        
    def add_packet(self, packet):
        """
        Add a packet to the buffer if it's not already present.
        
        Args:
            packet: The packet to add
        
        Returns:
            bool: True if packet was added, False if already in buffer
        """
        with self.lock:
            # Extract sequence number
            if packet.haslayer(TCP):
                seq_num = packet[TCP].seq
                
                # Check if this sequence number is already in the buffer
                if seq_num in self.sequence_numbers:
                    return False
                
                # Add packet to buffer
                self.packets.append(packet)
                self.sequence_numbers.add(seq_num)
                
                # Trim buffer if it exceeds max size
                if len(self.packets) > self.max_size:
                    removed_packet = self.packets.pop(0)
                    self.sequence_numbers.remove(removed_packet[TCP].seq)
                
                return True
            return False
    
    def get_sorted_packets(self) -> List:
        """
        Return packets sorted by sequence number.
        
        Returns:
            List: Sorted list of packets
        """
        with self.lock:
            if not self.packets:
                return []
            
            # Return a copy of packets sorted by sequence number
            return sorted(self.packets, key=lambda p: p[TCP].seq)
    
    def find_missing_sequences(self) -> List[int]:
        """
        Find missing sequence numbers in the stream.
        
        Returns:
            List[int]: List of missing sequence numbers
        """
        with self.lock:
            if len(self.packets) < 2:
                return []
            
            sorted_packets = self.get_sorted_packets()
            missing_seqs = []
            
            for i in range(len(sorted_packets) - 1):
                curr_seq = sorted_packets[i][TCP].seq
                curr_payload_len = len(sorted_packets[i][TCP].payload) if sorted_packets[i].haslayer(Raw) else 0
                expected_next_seq = curr_seq + curr_payload_len
                
                actual_next_seq = sorted_packets[i+1][TCP].seq
                
                # Check if there's a gap
                if actual_next_seq > expected_next_seq:
                    # Add all missing sequence numbers in the gap
                    missing_seqs.extend(range(expected_next_seq, actual_next_seq))
            
            return missing_seqs

class PacketCapture:
    """Captures packets from a network interface and reconstructs TCP streams."""
    
    def __init__(self, interface: str = None, filter_str: str = "tcp", buffer_size: int = 1000):
        """
        Initialize the packet capture system.
        
        Args:
            interface: Network interface to capture packets from (None for all interfaces)
            filter_str: BPF filter string to filter captured packets
            buffer_size: Maximum number of packets to store in each stream buffer
        """
        self.interface = interface
        self.filter_str = filter_str
        self.buffer_size = buffer_size
        self.stream_buffers = defaultdict(lambda: StreamBuffer(max_size=buffer_size))
        self.running = False
        self.capture_thread = None
        self.packet_callbacks = []
        self.missing_seq_callbacks = []
        
    def _packet_handler(self, packet):
        """
        Process captured packets.
        
        Args:
            packet: Captured packet
        """
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return
        
        # Create a stream identifier based on source and destination
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        # Normalize the stream ID so it's the same regardless of direction
        if (src_ip, src_port) > (dst_ip, dst_port):
            stream_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        else:
            stream_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        
        # Add packet to the appropriate stream buffer
        buffer = self.stream_buffers[stream_id]
        packet_added = buffer.add_packet(packet)
        
        # If packet was added (not a duplicate), check for missing sequences
        if packet_added:
            # Notify packet callbacks
            for callback in self.packet_callbacks:
                callback(stream_id, packet)
            
            # Check for missing sequences
            missing_seqs = buffer.find_missing_sequences()
            
            # Notify missing sequence callbacks
            if missing_seqs:
                for callback in self.missing_seq_callbacks:
                    callback(stream_id, missing_seqs, buffer.get_sorted_packets())
    
    def start_capture(self):
        """Start capturing packets."""
        if self.running:
            return
        
        self.running = True
        
        def capture_thread_func():
            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self._packet_handler,
                store=False,
                session=TCPSession,
                stop_filter=lambda p: not self.running
            )
        
        self.capture_thread = threading.Thread(target=capture_thread_func)
        self.capture_thread.daemon = True
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop capturing packets."""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
    
    def register_packet_callback(self, callback: Callable):
        """
        Register a callback function to be called when a new packet is added.
        
        Args:
            callback: Function taking (stream_id, packet) as arguments
        """
        self.packet_callbacks.append(callback)
    
    def register_missing_seq_callback(self, callback: Callable):
        """
        Register a callback function to be called when missing sequences are detected.
        
        Args:
            callback: Function taking (stream_id, missing_seqs, sorted_packets) as arguments
        """
        self.missing_seq_callbacks.append(callback)
    
    def get_stream_buffer(self, stream_id: str) -> Optional[StreamBuffer]:
        """
        Get the buffer for a specific stream.
        
        Args:
            stream_id: Stream identifier
            
        Returns:
            StreamBuffer or None if stream not found
        """
        return self.stream_buffers.get(stream_id)
    
    def get_all_stream_ids(self) -> List[str]:
        """
        Get a list of all active stream IDs.
        
        Returns:
            List[str]: List of stream identifiers
        """
        return list(self.stream_buffers.keys())
