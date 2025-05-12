#!/usr/bin/env python3
"""
knn_model.py - Implementation of K-Nearest Neighbors for packet prediction

This module provides a KNN-based model for predicting the content of missing
TCP packets based on surrounding packets in the stream.
"""

import pickle
import numpy as np
from typing import List, Dict, Tuple, Optional, Any
from sklearn.neighbors import KNeighborsRegressor
from sklearn.preprocessing import StandardScaler
from scapy.all import IP, TCP, Raw

class PacketFeatureExtractor:
    """Extract features from TCP packets for use in machine learning models."""
    
    @staticmethod
    def extract_features(packet) -> np.ndarray:
        """
        Extract features from a packet.
        
        Args:
            packet: The packet to extract features from
            
        Returns:
            np.ndarray: Feature vector for the packet
        """
        features = []
        
        # IP layer features
        if packet.haslayer(IP):
            features.extend([
                packet[IP].ttl,
                packet[IP].len,
                packet[IP].id,
                len(packet[IP])
            ])
        else:
            features.extend([0, 0, 0, 0])  # Default values if no IP layer
        
        # TCP layer features
        if packet.haslayer(TCP):
            features.extend([
                packet[TCP].sport,
                packet[TCP].dport,
                packet[TCP].seq,
                packet[TCP].ack,
                packet[TCP].window,
                packet[TCP].flags.value
            ])
        else:
            features.extend([0, 0, 0, 0, 0, 0])  # Default values if no TCP layer
        
        # Payload features
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            features.extend([
                len(payload),
                np.mean(payload) if payload else 0,
                np.std(payload) if len(payload) > 1 else 0,
                np.max(payload) if payload else 0,
                np.min(payload) if payload else 0
            ])
        else:
            features.extend([0, 0, 0, 0, 0])  # Default values if no payload
        
        return np.array(features, dtype=np.float32)
    
    @staticmethod
    def extract_payload(packet) -> bytes:
        """
        Extract the payload from a packet.
        
        Args:
            packet: The packet to extract payload from
            
        Returns:
            bytes: Payload of the packet or empty bytes
        """
        if packet.haslayer(Raw):
            return bytes(packet[Raw])
        return b''
    
    @staticmethod
    def extract_sequence_info(packet) -> Tuple[int, int]:
        """
        Extract sequence number and payload length from a packet.
        
        Args:
            packet: The packet to extract sequence info from
            
        Returns:
            Tuple[int, int]: (sequence number, payload length)
        """
        seq_num = packet[TCP].seq if packet.haslayer(TCP) else 0
        payload_len = len(packet[Raw]) if packet.haslayer(Raw) else 0
        return seq_num, payload_len

class KNNModel:
    """KNN-based model for predicting missing packet contents."""
    
    def __init__(self, n_neighbors: int = 5, weights: str = 'distance'):
        """
        Initialize the KNN model.
        
        Args:
            n_neighbors: Number of neighbors to use in KNN
            weights: Weight function used in prediction ('uniform' or 'distance')
        """
        self.n_neighbors = n_neighbors
        self.weights = weights
        self.feature_extractor = PacketFeatureExtractor()
        self.feature_scaler = StandardScaler()
        self.payload_model = KNeighborsRegressor(
            n_neighbors=n_neighbors,
            weights=weights,
            algorithm='auto',
            n_jobs=-1
        )
        self.is_trained = False
    
    def _prepare_training_data(self, packets: List) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare training data from a list of packets.
        
        Args:
            packets: List of packets
            
        Returns:
            Tuple[np.ndarray, np.ndarray]: (features, target payloads)
        """
        if len(packets) < 2:
            raise ValueError("At least 2 packets are required for training")
        
        # Extract features and payloads
        features = []
        payloads = []
        
        for packet in packets:
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                features.append(self.feature_extractor.extract_features(packet))
                payloads.append(self.feature_extractor.extract_payload(packet))
        
        if not features:
            raise ValueError("No valid TCP packets with payloads found")
        
        # Convert payloads to numpy arrays of fixed size
        max_payload_len = max(len(p) for p in payloads)
        payload_arrays = []
        
        for payload in payloads:
            # Pad payloads to the same length
            padded = np.zeros(max_payload_len, dtype=np.uint8)
            padded[:len(payload)] = np.frombuffer(payload, dtype=np.uint8)
            payload_arrays.append(padded)
        
        return np.array(features), np.array(payload_arrays)
    
    def train(self, packets: List):
        """
        Train the KNN model with a list of packets.
        
        Args:
            packets: List of packets to train on
        """
        X, y = self._prepare_training_data(packets)
        
        # Scale features
        X_scaled = self.feature_scaler.fit_transform(X)
        
        # Train the model
        self.payload_model.fit(X_scaled, y)
        self.is_trained = True
    
    def save_model(self, filepath: str):
        """
        Save the trained model to a file.
        
        Args:
            filepath: Path to save the model
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        model_data = {
            'feature_scaler': self.feature_scaler,
            'payload_model': self.payload_model,
            'n_neighbors': self.n_neighbors,
            'weights': self.weights
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
    
    @classmethod
    def load_model(cls, filepath: str) -> 'KNNModel':
        """
        Load a trained model from a file.
        
        Args:
            filepath: Path to load the model from
            
        Returns:
            KNNModel: Loaded model
        """
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        model = cls(
            n_neighbors=model_data['n_neighbors'],
            weights=model_data['weights']
        )
        
        model.feature_scaler = model_data['feature_scaler']
        model.payload_model = model_data['payload_model']
        model.is_trained = True
        
        return model
    
    def predict_packet(self, 
                       feature_packet, 
                       seq_num: int, 
                       prev_packet=None, 
                       next_packet=None) -> bytes:
        """
        Predict the content of a missing packet.
        
        Args:
            feature_packet: A packet to extract features from (usually a copy of prev_packet)
            seq_num: The sequence number of the missing packet
            prev_packet: The packet before the missing one
            next_packet: The packet after the missing one
            
        Returns:
            bytes: Predicted payload for the missing packet
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        # Extract features from the template packet
        features = self.feature_extractor.extract_features(feature_packet)
        
        # Modify the sequence number to match the missing packet
        features[6] = seq_num  # Index 6 is the sequence number in our feature vector
        
        # Adjust features based on neighboring packets if available
        if prev_packet and next_packet:
            prev_features = self.feature_extractor.extract_features(prev_packet)
            next_features = self.feature_extractor.extract_features(next_packet)
            
            # Use some features from neighboring packets to improve prediction
            # For example, average the TTL, len, etc.
            for i in [0, 1, 2, 3]:  # IP layer features
                features[i] = (prev_features[i] + next_features[i]) / 2
            
            # For TCP flags, use bitwise OR to combine possible flags
            features[11] = prev_features[11] | next_features[11]  # TCP flags
        
        # Scale the features
        features_scaled = self.feature_scaler.transform(features.reshape(1, -1))
        
        # Predict payload
        predicted_payload_array = self.payload_model.predict(features_scaled)[0]
        
        # Convert the predicted array back to bytes
        # Find where the padding starts (first occurrence of multiple zeros)
        non_zero = np.where(predicted_payload_array > 0)[0]
        if len(non_zero) > 0:
            payload_len = non_zero[-1] + 1
        else:
            payload_len = 0
        
        predicted_payload = bytes(predicted_payload_array[:payload_len].astype(np.uint8))
        return predicted_payload

    def analyze_stream(self, packets: List) -> Dict[str, Any]:
        """
        Analyze a stream of packets to detect patterns.
        
        Args:
            packets: List of packets in the stream
            
        Returns:
            Dict: Analysis results including packet patterns and statistics
        """
        if len(packets) < 2:
            return {"error": "Not enough packets for analysis"}
        
        # Extract features and sequence info
        features = []
        seq_info = []
        
        for packet in packets:
            if packet.haslayer(TCP):
                features.append(self.feature_extractor.extract_features(packet))
                seq_info.append(self.feature_extractor.extract_sequence_info(packet))
        
        # Calculate gaps between sequence numbers
        gaps = []
        for i in range(len(seq_info) - 1):
            curr_seq, curr_len = seq_info[i]
            next_seq, _ = seq_info[i + 1]
            gap = next_seq - (curr_seq + curr_len)
            if gap > 0:
                gaps.append(gap)
        
        # Calculate payload size statistics
        payload_sizes = [s[1] for s in seq_info]
        
        return {
            "packet_count": len(packets),
            "avg_payload_size": np.mean(payload_sizes) if payload_sizes else 0,
            "std_payload_size": np.std(payload_sizes) if len(payload_sizes) > 1 else 0,
            "max_payload_size": np.max(payload_sizes) if payload_sizes else 0,
            "min_payload_size": np.min(payload_sizes) if payload_sizes else 0,
            "gap_count": len(gaps),
            "avg_gap_size": np.mean(gaps) if gaps else 0,
            "max_gap_size": np.max(gaps) if gaps else 0
        }
