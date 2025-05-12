#!/usr/bin/env python3
"""
advanced_recovery.py - Example of advanced TCP packet recovery

This example demonstrates how to use the TCP Packet Recovery package
to monitor TCP streams, detect missing packets, and inject reconstructed
packets to recover from packet loss.
"""

import time
import logging
import argparse
import json
from tcp_packet_recovery import PacketMonitor, KNNModel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Advanced TCP Recovery Example')
    parser.add_argument('-i', '--interface', help='Network interface to capture packets from')
    parser.add_argument('-f', '--filter', default='tcp', help='BPF filter string')
    parser.add_argument('-m', '--model', help='Path to pre-trained KNN model')
    parser.add_argument('-c', '--confidence', type=float, default=0.7, 
                       help='Confidence threshold for packet injection')
    parser.add_argument('-t', '--training-time', type=float, default=30.0,
                       help='Training time in seconds if no model is provided')
    parser.add_argument('-d', '--duration', type=int, default=300,
                       help='Duration to monitor in seconds')
    parser.add_argument('-o', '--output', default='recovery_stats.json',
                       help='Path to output statistics file')
    
    args = parser.parse_args()
    
    # Create a packet monitor with advanced settings
    monitor = PacketMonitor(
        interface=args.interface,
        filter_str=args.filter,
        knn_model_path=args.model,
        confidence_threshold=args.confidence,
        visualization=True,  # Enable visualization
        db_url="sqlite:///advanced_recovery.db"  # Use a specific database file
    )
    
    try:
        # Start the monitor
        logger.info(f"Starting TCP stream monitoring and recovery for {args.duration} seconds...")
        monitor.start(training_time=args.training_time, train_model=not bool(args.model))
        
        # Record statistics at regular intervals
        stats_history = []
        start_time = time.time()
        end_time = start_time + args.duration
        
        while time.time() < end_time:
            # Get current statistics
            current_stats = monitor.get_statistics()
            
            # Add timestamp
            current_stats['timestamp'] = time.time()
            
            # Add to history
            stats_history.append(current_stats)
            
            # Print summary
            total_streams = len(current_stats['streams'])
            total_packets = sum(s.get('total_packets', 0) for s in current_stats['streams'].values())
            total_missing = sum(s.get('missing_packets', 0) for s in current_stats['streams'].values())
            total_injected = sum(s.get('injected_packets', 0) for s in current_stats['streams'].values())
            
            logger.info(f"Current status: {total_streams} streams, "
                       f"{total_packets} packets, {total_missing} missing, "
                       f"{total_injected} injected")
            
            # Calculate recovery rate
            if total_missing > 0:
                recovery_rate = total_injected / total_missing
                logger.info(f"Recovery rate: {recovery_rate:.2%}")
            
            # Sleep for 10 seconds
            time.sleep(10)
        
        # Stop the monitor
        logger.info("Stopping TCP stream monitoring and recovery...")
        monitor.stop()
        
        # Save statistics to file
        with open(args.output, 'w') as f:
            json.dump(stats_history, f, indent=2)
        
        logger.info(f"Statistics saved to {args.output}")
        
    except KeyboardInterrupt:
        logger.info("Monitoring interrupted by user")
        monitor.stop()
    
    logger.info("Monitoring and recovery completed")

if __name__ == '__main__':
    main()
