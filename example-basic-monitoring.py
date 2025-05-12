#!/usr/bin/env python3
"""
basic_monitoring.py - Example of basic TCP stream monitoring

This example demonstrates how to use the TCP Packet Recovery package
to monitor TCP streams and detect missing packets.
"""

import time
import logging
import argparse
from tcp_packet_recovery import PacketMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Basic TCP Monitoring Example')
    parser.add_argument('-i', '--interface', help='Network interface to capture packets from')
    parser.add_argument('-f', '--filter', default='tcp', help='BPF filter string')
    parser.add_argument('-d', '--duration', type=int, default=60, help='Duration to monitor in seconds')
    
    args = parser.parse_args()
    
    # Create a packet monitor
    monitor = PacketMonitor(
        interface=args.interface,
        filter_str=args.filter,
        visualization=True  # Enable visualization
    )
    
    try:
        # Start the monitor
        logger.info(f"Starting TCP stream monitoring for {args.duration} seconds...")
        monitor.start(training_time=10, train_model=True)
        
        # Monitor for the specified duration
        end_time = time.time() + args.duration
        while time.time() < end_time:
            # Print statistics every 5 seconds
            stats = monitor.get_statistics()
            logger.info(f"Active streams: {len(stats['streams'])}")
            
            for stream_id, stream_stats in stats['streams'].items():
                logger.info(f"Stream {stream_id}: "
                          f"{stream_stats['total_packets']} packets, "
                          f"{stream_stats['missing_packets']} missing, "
                          f"{stream_stats['injected_packets']} injected")
            
            time.sleep(5)
        
        # Stop the monitor
        logger.info("Stopping TCP stream monitoring...")
        monitor.stop()
        
    except KeyboardInterrupt:
        logger.info("Monitoring interrupted by user")
        monitor.stop()
    
    logger.info("Monitoring completed")

if __name__ == '__main__':
    main()
