#!/usr/bin/env python3
"""
test_knn_model.py - Tests for the KNN model implementation

This module contains unit tests for the KNN model used to predict
missing TCP packets.
"""

import unittest
import os
import tempfile
import numpy as np
from scapy.all import IP, TCP, Raw, Ether

# Import KNN model
from tcp_packet_recovery.knn_model import KNNModel, PacketFeatureExtractor

class TestPacketFeatureExtractor(unittest.TestCase):
    """Tests for the PacketFeatureExtractor class."""
    
    def setUp(self):
        """Set up test environment."""
        self.extractor = PacketFeatureExtractor()
        
        # Create a sample packet
        self.sample_packet = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
            IP(src="192.168.1.1", dst="10.0.0.1") /
            TCP(sport=12345, dport=80, seq=1000, ack=2000, flags="PA") /
            Raw(load=b"Hello, World!")
        )
    
    def test_extract_features(self):
        """Test feature extraction from a packet."""
        features = self.extractor.extract_features(self.sample_packet)
        
        # Check feature vector type
        self.assertIsInstance(features, np.ndarray)
        
        # Feature vector should have the right length
        # 4 IP features + 6 TCP features + 5 payload features = 15 features
        self.assertEqual(len(features), 15)
        
        # Check that features have sensible values
        # IP TTL
        self.assertEqual(features[0], self.sample_packet[IP].ttl)
        # IP length
        self.assertEqual(features[1], self.sample_packet[IP].len)
        # TCP sequence number
        self.assertEqual(features[6], self.sample_packet[TCP].seq)
        # Payload length
        self.assertEqual(features[10], len(b"Hello, World!"))
    
    def test_extract_payload(self):
        """Test payload extraction from a packet."""
        payload = self.extractor.extract_payload(self.sample_packet)
        
        # Check payload type and content
        self.assertEqual(payload, b"Hello, World!")
    
    def test_extract_sequence_info(self):
        """Test extraction of sequence information."""
        seq_num, payload_len = self.extractor.extract_sequence_info(self.sample_packet)
        
        # Check sequence number
        self.assertEqual(seq_num, 1000)
        # Check payload length
        self.assertEqual(payload_len, len(b"Hello, World!"))

class TestKNNModel(unittest.TestCase):
    """Tests for the KNNModel class."""
    
    def setUp(self):
        """Set up test environment."""
        self.model = KNNModel(n_neighbors=3)
        
        # Create sample packets
        self.sample_packets = []
        for i in range(20):
            # Create packets with varying sequence numbers and payloads
            packet = (
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
                IP(src="192.168.1.1", dst="10.0.0.1") /
                TCP(sport=12345, dport=80, seq=1000 + i * 100, ack=2000, flags="PA") /
                Raw(load=bytes([i % 256] * (50 + i)))
            )
            self.sample_packets.append(packet)
    
    def test_train_and_predict(self):
        """Test training the model and predicting a packet."""
        # Train the model
        self.model.train(self.sample_packets)
        
        # Check that the model is trained
        self.assertTrue(self.model.is_trained)
        
        # Create a template packet with a known sequence number
        template_packet = self.sample_packets[0].copy()
        seq_num = 1250  # Between packet 2 (seq 1200) and 3 (seq 1300)
        
        # Predict a packet
        predicted_payload = self.model.predict_packet(
            template_packet,
            seq_num,
            self.sample_packets[2],  # Previous packet
            self.sample_packets[3]   # Next packet
        )
        
        # Check that the prediction is a bytes object
        self.assertIsInstance(predicted_payload, bytes)
        
        # The payload size should be reasonable (between the sizes of neighboring packets)
        self.assertGreaterEqual(len(predicted_payload), len(self.sample_packets[2][Raw]))
        self.assertLessEqual(len(predicted_payload), len(self.sample_packets[3][Raw]))
    
    def test_save_and_load(self):
        """Test saving and loading the model."""
        # Train the model
        self.model.train(self.sample_packets)
        
        # Save the model to a temporary file
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as tmp:
            model_path = tmp.name
        
        self.model.save_model(model_path)
        
        # Load the model
        loaded_model = KNNModel.load_model(model_path)
        
        # Check that the loaded model is trained
        self.assertTrue(loaded_model.is_trained)
        
        # Check that the loaded model has the same parameters
        self.assertEqual(loaded_model.n_neighbors, self.model.n_neighbors)
        self.assertEqual(loaded_model.weights, self.model.weights)
        
        # Clean up
        os.unlink(model_path)
    
    def test_analyze_stream(self):
        """Test analyzing a stream of packets."""
        # Train the model
        self.model.train(self.sample_packets)
        
        # Analyze the stream
        analysis = self.model.analyze_stream(self.sample_packets)
        
        # Check that the analysis contains the expected keys
        self.assertIn('packet_count', analysis)
        self.assertIn('avg_payload_size', analysis)
        self.assertIn('gap_count', analysis)
        
        # Check that the packet count is correct
        self.assertEqual(analysis['packet_count'], len(self.sample_packets))
        
        # The average payload size should be positive
        self.assertGreater(analysis['avg_payload_size'], 0)

if __name__ == '__main__':
    unittest.main()
