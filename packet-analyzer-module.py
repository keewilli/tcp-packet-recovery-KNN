#!/usr/bin/env python3
"""
packet_analyzer.py - Module for analyzing TCP packet streams and detecting missing packets

This module analyzes TCP streams to detect missing packets and provides interfaces
for processing and analyzing packet loss patterns.
"""

import time
import threading
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Callable, Set

import numpy as np
from scapy.all import IP, TCP, Raw

from .packet_capture import PacketCapture, StreamBuffer
from .knn_model import KNNModel

class PacketAnalyzer:
    """Analyzes TCP packet streams to detect missing packets."""
    
    def __init__(self, 
                 packet_capture: PacketCapture,
                 knn_model: Optional[KNNModel] = None,
                 analysis_interval: float = 1.0,
                 min_packets_for_analysis: int = 10):
        """
        Initialize the packet analyzer.
        
        Args:
            packet_capture: PacketCapture instance to get packets from
            knn_model: Optional KNN model for packet prediction
            analysis_interval: How often to analyze streams (in seconds)
            min_packets_for_analysis: Minimum number of packets required for analysis
        """
        self.packet_capture = packet_capture
        self.knn_model = knn_model
        self.analysis_interval = analysis_interval
        self.min_packets_for_analysis = min_packets_for_analysis
        self.missing_packet_handlers = []
        self.stream_analysis_handlers = []
        self.running = False
        self.analysis_thread = None
        self.last_analysis_times = defaultdict(float)
        self.detected_missing_packets = defaultdict(set)  # Store detected missing packets by stream_id
    
    def register_missing_packet_handler(self, handler: Callable):
        """
        Register a handler to be called when a missing packet is detected.
        
        Args:
            handler: Function taking (stream_id, seq_num, prev_packet, next_packet) as arguments
        """
        self.missing_packet_handlers.append(handler)
    
    def register_stream_analysis_handler(self, handler: Callable):
        """
        Register a handler to be called when a stream is analyzed.
        
        Args:
            handler: Function taking (stream_id, analysis_results) as arguments
        """
        self.stream_analysis_handlers.append(handler)
    
    def _notify_missing_packet(self, stream_id: str, seq_num: int, prev_packet, next_packet):
        """
        Notify all registered handlers about a missing packet.
        
        Args:
            stream_id: Stream identifier
            seq_num: Sequence number of the missing packet
            prev_packet: Packet before the missing one
            next_packet: Packet after the missing one
        """
        # Check if this missing packet was already detected
        if seq_num in self.detected_missing_packets[stream_id]:
            return
        
        # Add to detected set
        self.detected_missing_packets[stream_id].add(seq_num)
        
        # Notify handlers
        for handler in self.missing_packet_handlers:
            handler(stream_id, seq_num, prev_packet, next_packet)
    
    def _notify_stream_analysis(self, stream_id: str, analysis_results: Dict):
        """
        Notify all registered handlers about stream analysis results.
        
        Args:
            stream_id: Stream identifier
            analysis_results: Results of the analysis
        """
        for handler in self.stream_analysis_handlers:
            handler(stream_id, analysis_results)
    
    def _find_neighboring_packets(self, packets: List, seq_num: int) -> Tuple[Optional, Optional]:
        """
        Find packets immediately before and after a given sequence number.
        
        Args:
            packets: List of packets
            seq_num: Sequence number to find neighbors for
            
        Returns:
            Tuple: (previous packet, next packet) or (None, None) if not found
        """
        prev_packet = None
        next_packet = None
        
        for i, packet in enumerate(packets):
            if not packet.haslayer(TCP):
                continue
                
            if packet[TCP].seq < seq_num:
                # This could be a previous packet
                if prev_packet is None or packet[TCP].seq > prev_packet[TCP].seq:
                    prev_packet = packet
            elif packet[TCP].seq > seq_num:
                # This could be a next packet
                if next_packet is None or packet[TCP].seq < next_packet[TCP].seq:
                    next_packet = packet
        
        return prev_packet, next_packet
    
    def analyze_stream(self, stream_id: str, force: bool = False) -> Optional[Dict]:
        """
        Analyze a specific stream for missing packets.
        
        Args:
            stream_id: Stream identifier
            force: Force analysis even if not enough time has passed
            
        Returns:
            Dict: Analysis results or None if analysis was not performed
        """
        # Check if enough time has passed since last analysis
        current_time = time.time()
        if not force and (current_time - self.last_analysis_times[stream_id]) < self.analysis_interval:
            return None
        
        # Get the stream buffer
        buffer = self.packet_capture.get_stream_buffer(stream_id)
        if buffer is None:
            return None
        
        # Get sorted packets
        packets = buffer.get_sorted_packets()
        if len(packets) < self.min_packets_for_analysis:
            return None
        
        # Find missing sequence numbers
        missing_seqs = buffer.find_missing_sequences()
        
        # Perform analysis with KNN model if available
        analysis_results = {
            "stream_id": stream_id,
            "packet_count": len(packets),
            "missing_packet_count": len(missing_seqs),
            "analysis_time": current_time,
            "missing_sequences": missing_seqs
        }
        
        if self.knn_model and len(packets) >= self.min_packets_for_analysis:
            try:
                # Analyze the stream with the KNN model
                knn_analysis = self.knn_model.analyze_stream(packets)
                analysis_results.update(knn_analysis)
            except Exception as e:
                analysis_results["knn_error"] = str(e)
        
        # For each missing sequence, find neighboring packets
        for seq_num in missing_seqs:
            prev_packet, next_packet = self._find_neighboring_packets(packets, seq_num)
            if prev_packet and next_packet:
                self._notify_missing_packet(stream_id, seq_num, prev_packet, next_packet)
        
        # Notify stream analysis handlers
        self._notify_stream_analysis(stream_id, analysis_results)
        
        # Update last analysis time
        self.last_analysis_times[stream_id] = current_time
        
        return analysis_results
    
    def _analysis_thread_func(self):
        """Thread function for continuous stream analysis."""
        while self.running:
            # Get all stream IDs
            stream_ids = self.packet_capture.get_all_stream_ids()
            
            # Analyze each stream
            for stream_id in stream_ids:
                self.analyze_stream(stream_id)
            
            # Sleep for a short period
            time.sleep(0.1)
    
    def start_analysis(self):
        """Start continuous analysis."""
        if self.running:
            return
        
        self.running = True
        self.analysis_thread = threading.Thread(target=self._analysis_thread_func)
        self.analysis_thread.daemon = True
        self.analysis_thread.start()
    
    def stop_analysis(self):
        """Stop continuous analysis."""
        self.running = False
        if self.analysis_thread:
            self.analysis_thread.join(timeout=2.0)
    
    def clear_detected_missing_packets(self, stream_id: Optional[str] = None):
        """
        Clear the set of detected missing packets.
        
        Args:
            stream_id: Specific stream to clear, or all streams if None
        """
        if stream_id:
            self.detected_missing_packets[stream_id] = set()
        else:
            self.detected_missing_packets.clear()
            
    def get_missing_packet_statistics(self) -> Dict:
        """
        Get statistics about missing packets.
        
        Returns:
            Dict: Statistics about missing packets
        """
        stats = {
            "total_streams": len(self.detected_missing_packets),
            "total_missing_packets": sum(len(packets) for packets in self.detected_missing_packets.values()),
            "streams_with_missing_packets": sum(1 for packets in self.detected_missing_packets.values() if packets),
            "per_stream_stats": {}
        }
        
        for stream_id, missing_packets in self.detected_missing_packets.items():
            buffer = self.packet_capture.get_stream_buffer(stream_id)
            if buffer:
                total_packets = len(buffer.packets)
                stats["per_stream_stats"][stream_id] = {
                    "missing_packets": len(missing_packets),
                    "total_packets": total_packets,
                    "packet_loss_rate": len(missing_packets) / total_packets if total_packets > 0 else 0
                }
        
        return stats