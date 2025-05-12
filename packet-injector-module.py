#!/usr/bin/env python3
"""
packet_injector.py - Module for reconstructing and injecting missing TCP packets

This module uses the KNN model to predict the content of missing packets and
injects them back into the TCP stream.
"""

import time
import threading
import socket
import logging
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Set

from scapy.all import IP, TCP, Raw, send
from scapy.layers.inet import IPerror, TCPerror

from .knn_model import KNNModel

logger = logging.getLogger(__name__)

class PacketInjector:
    """Reconstructs and injects missing TCP packets."""
    
    def __init__(self, knn_model: KNNModel, confidence_threshold: float = 0.7):
        """
        Initialize the packet injector.
        
        Args:
            knn_model: KNN model for packet prediction
            confidence_threshold: Minimum confidence required for injection
        """
        self.knn_model = knn_model
        self.confidence_threshold = confidence_threshold
        self.injection_queue = defaultdict(list)  # Queue of packets to inject by stream_id
        self.injection_thread = None
        self.running = False
        self.injection_stats = defaultdict(int)  # Statistics by stream_id
        self.injected_seq_nums = defaultdict(set)  # Set of injected sequence numbers by stream_id
        self.injection_callbacks = []  # Callbacks for successful injections
    
    def register_injection_callback(self, callback):
        """
        Register a callback to be called when a packet is injected.
        
        Args:
            callback: Function taking (stream_id, seq_num, injected_packet) as arguments
        """
        self.injection_callbacks.append(callback)
    
    def _parse_stream_id(self, stream_id: str) -> Tuple[str, int, str, int]:
        """
        Parse a stream_id into IP addresses and ports.
        
        Args:
            stream_id: Stream identifier in the format "ip1:port1-ip2:port2"
            
        Returns:
            Tuple[str, int, str, int]: (src_ip, src_port, dst_ip, dst_port)
        """
        try:
            endpoints = stream_id.split('-')
            src = endpoints[0].split(':')
            dst = endpoints[1].split(':')
            return src[0], int(src[1]), dst[0], int(dst[1])
        except (IndexError, ValueError) as e:
            logger.error(f"Failed to parse stream_id {stream_id}: {e}")
            raise ValueError(f"Invalid stream_id format: {stream_id}")
    
    def queue_packet_for_injection(self, 
                                  stream_id: str, 
                                  seq_num: int, 
                                  prev_packet, 
                                  next_packet):
        """
        Queue a missing packet for reconstruction and injection.
        
        Args:
            stream_id: Stream identifier
            seq_num: Sequence number of the missing packet
            prev_packet: Packet before the missing one
            next_packet: Packet after the missing one
        """
        # Check if this sequence number was already injected
        if seq_num in self.injected_seq_nums[stream_id]:
            return
        
        # Create an entry in the injection queue
        self.injection_queue[stream_id].append({
            'seq_num': seq_num,
            'prev_packet': prev_packet,
            'next_packet': next_packet,
            'timestamp': time.time()
        })
    
    def _reconstruct_packet(self, 
                          stream_id: str, 
                          seq_num: int, 
                          prev_packet, 
                          next_packet) -> Optional[Tuple[bytes, float]]:
        """
        Reconstruct a missing packet using the KNN model.
        
        Args:
            stream_id: Stream identifier
            seq_num: Sequence number of the missing packet
            prev_packet: Packet before the missing one
            next_packet: Packet after the missing one
            
        Returns:
            Tuple[bytes, float] or None: (Reconstructed packet payload, confidence)
        """
        try:
            # Use the KNN model to predict the packet payload
            if prev_packet and next_packet:
                # Create a template packet based on the previous packet
                template_packet = prev_packet.copy()
                
                # Predict the payload
                predicted_payload = self.knn_model.predict_packet(
                    template_packet, seq_num, prev_packet, next_packet
                )
                
                # Calculate confidence (simplified)
                # In a real implementation, this would be based on the KNN model's prediction confidence
                # For now, we just use a heuristic based on the payload size
                avg_payload_size = (len(prev_packet[Raw]) if prev_packet.haslayer(Raw) else 0 +
                                   len(next_packet[Raw]) if next_packet.haslayer(Raw) else 0) / 2
                
                if avg_payload_size > 0:
                    confidence = min(1.0, len(predicted_payload) / avg_payload_size)
                else:
                    confidence = 0.5  # Default confidence
                
                return predicted_payload, confidence
            
            return None, 0.0
        except Exception as e:
            logger.error(f"Failed to reconstruct packet {seq_num} in stream {stream_id}: {e}")
            return None, 0.0
    
    def _create_injection_packet(self, 
                               stream_id: str, 
                               seq_num: int, 
                               payload: bytes, 
                               prev_packet,
                               next_packet) -> Optional:
        """
        Create a packet for injection.
        
        Args:
            stream_id: Stream identifier
            seq_num: Sequence number of the missing packet
            payload: Payload for the packet
            prev_packet: Packet before the missing one
            next_packet: Packet after the missing one
            
        Returns:
            Packet: Scapy packet ready for injection or None if creation failed
        """
        try:
            # Parse the stream_id to get IP addresses and ports
            src_ip, src_port, dst_ip, dst_port = self._parse_stream_id(stream_id)
            
            # Determine direction based on sequence number
            # If seq_num is closer to prev_packet's seq, use prev_packet's direction
            # Otherwise, use next_packet's direction
            if (prev_packet and prev_packet.haslayer(TCP) and 
                next_packet and next_packet.haslayer(TCP)):
                
                prev_seq = prev_packet[TCP].seq
                next_seq = next_packet[TCP].seq
                
                if abs(seq_num - prev_seq) < abs(seq_num - next_seq):
                    # Use prev_packet's direction
                    if prev_packet[IP].src == src_ip:
                        # Same direction as stream_id
                        packet_src_ip = src_ip
                        packet_src_port = src_port
                        packet_dst_ip = dst_ip
                        packet_dst_port = dst_port
                    else:
                        # Opposite direction
                        packet_src_ip = dst_ip
                        packet_src_port = dst_port
                        packet_dst_ip = src_ip
                        packet_dst_port = src_port
                else:
                    # Use next_packet's direction
                    if next_packet[IP].src == src_ip:
                        # Same direction as stream_id
                        packet_src_ip = src_ip
                        packet_src_port = src_port
                        packet_dst_ip = dst_ip
                        packet_dst_port = dst_port
                    else:
                        # Opposite direction
                        packet_src_ip = dst_ip
                        packet_src_port = dst_port
                        packet_dst_ip = src_ip
                        packet_dst_port = src_port
            else:
                # Default to the direction specified in stream_id
                packet_src_ip = src_ip
                packet_src_port = src_port
                packet_dst_ip = dst_ip
                packet_dst_port = dst_port
            
            # Create the packet
            if prev_packet and prev_packet.haslayer(TCP):
                # Copy most TCP flags and options from prev_packet
                tcp_flags = prev_packet[TCP].flags
                tcp_options = prev_packet[TCP].options
                tcp_window = prev_packet[TCP].window
                
                # Calculate the acknowledgment number
                if next_packet and next_packet.haslayer(TCP):
                    tcp_ack = next_packet[TCP].ack
                else:
                    # If no next_packet, use prev_packet's ack
                    tcp_ack = prev_packet[TCP].ack
            else:
                # Default TCP values
                tcp_flags = 'PA'  # Push + ACK
                tcp_options = []
                tcp_window = 8192
                tcp_ack = 0
            
            # Create the injection packet
            injection_packet = (
                IP(src=packet_src_ip, dst=packet_dst_ip) /
                TCP(sport=packet_src_port, dport=packet_dst_port,
                   seq=seq_num, ack=tcp_ack,
                   flags=tcp_flags, window=tcp_window,
                   options=tcp_options) /
                Raw(load=payload)
            )
            
            return injection_packet
        except Exception as e:
            logger.error(f"Failed to create injection packet for {seq_num} in stream {stream_id}: {e}")
            return None
    
    def _inject_packet(self, packet) -> bool:
        """
        Inject a packet into the network.
        
        Args:
            packet: Packet to inject
            
        Returns:
            bool: True if injection was successful, False otherwise
        """
        try:
            # Send the packet with Scapy
            send(packet, verbose=0)
            return True
        except Exception as e:
            logger.error(f"Failed to inject packet: {e}")
            return False
    
    def _process_injection_queue(self):
        """Process the injection queue and inject packets."""
        while self.running:
            # Process each stream's queue
            for stream_id in list(self.injection_queue.keys()):
                # Get the queue for this stream
                queue = self.injection_queue[stream_id]
                
                # Process each packet in the queue
                for i in range(len(queue) - 1, -1, -1):  # Process in reverse order to allow removal
                    entry = queue[i]
                    seq_num = entry['seq_num']
                    prev_packet = entry['prev_packet']
                    next_packet = entry['next_packet']
                    
                    # Skip if already injected
                    if seq_num in self.injected_seq_nums[stream_id]:
                        queue.pop(i)
                        continue
                    
                    # Reconstruct the packet
                    payload, confidence = self._reconstruct_packet(
                        stream_id, seq_num, prev_packet, next_packet
                    )
                    
                    # Skip if confidence is too low
                    if confidence < self.confidence_threshold or payload is None:
                        logger.debug(f"Skipping packet {seq_num} in stream {stream_id}: confidence {confidence:.2f} < threshold {self.confidence_threshold}")
                        continue
                    
                    # Create the injection packet
                    injection_packet = self._create_injection_packet(
                        stream_id, seq_num, payload, prev_packet, next_packet
                    )
                    
                    if injection_packet:
                        # Inject the packet
                        success = self._inject_packet(injection_packet)
                        
                        if success:
                            # Update statistics
                            self.injection_stats[stream_id] += 1
                            self.injected_seq_nums[stream_id].add(seq_num)
                            
                            # Log the injection
                            logger.info(f"Injected packet {seq_num} in stream {stream_id} with confidence {confidence:.2f}")
                            
                            # Notify callbacks
                            for callback in self.injection_callbacks:
                                callback(stream_id, seq_num, injection_packet)
                        
                        # Remove from queue
                        queue.pop(i)
            
            # Sleep for a short period
            time.sleep(0.01)
    
    def start_injection(self):
        """Start the injection thread."""
        if self.running:
            return
        
        self.running = True
        self.injection_thread = threading.Thread(target=self._process_injection_queue)
        self.injection_thread.daemon = True
        self.injection_thread.start()
    
    def stop_injection(self):
        """Stop the injection thread."""
        self.running = False
        if self.injection_thread:
            self.injection_thread.join(timeout=2.0)
    
    def get_injection_statistics(self) -> Dict:
        """
        Get statistics about packet injections.
        
        Returns:
            Dict: Statistics about packet injections
        """
        total_injected = sum(self.injection_stats.values())
        stats = {
            "total_streams": len(self.injection_stats),
            "total_injected_packets": total_injected,
            "streams_with_injections": sum(1 for count in self.injection_stats.values() if count > 0),
            "per_stream_stats": self.injection_stats.copy()
        }
        return stats
