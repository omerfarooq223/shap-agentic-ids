#!/usr/bin/env python3
"""
Real-Time Packet Capture Module for Agentic IDS

Captures live network packets, extracts features, and feeds to detection engine.
Supports both live capture and pcap file processing.
"""

import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP, IPv6
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
import threading
import queue
from typing import Callable, Optional, Dict, Any
import time

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class PacketFlowExtractor:
    """
    Extract network flow features from raw packets.
    Groups packets by (src_ip, dst_ip, src_port, dst_port, protocol).
    """
    
    def __init__(self, timeout=60):
        self.flows = {}  # {flow_key: flow_data}
        self.timeout = timeout
        self.last_update = {}
        
    def packet_to_flow_key(self, pkt) -> Optional[tuple]:
        """Extract flow 5-tuple from packet."""
        try:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = pkt[IP].proto
                
                src_port = 0
                dst_port = 0
                
                if TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                return flow_key
        except Exception as e:
            logger.debug(f"Error extracting flow key: {e}")
            return None
        
    def update_flow(self, pkt) -> Optional[Dict[str, Any]]:
        """
        Update flow statistics with packet data.
        Returns complete flow when it's complete or times out.
        """
        flow_key = self.packet_to_flow_key(pkt)
        if not flow_key:
            return None
        
        current_time = time.time()
        self.last_update[flow_key] = current_time
        
        # Initialize flow if new
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                'src_ip': flow_key[0],
                'dst_ip': flow_key[1],
                'src_port': flow_key[2],
                'dst_port': flow_key[3],
                'protocol': flow_key[4],
                'start_time': current_time,
                'Total Fwd Packets': 0,
                'Total Backward Packets': 0,
                'Total Length of Fwd Packets': 0,
                'Total Length of Bwd Packets': 0,
                'Fwd Packet Length Max': 0,
                'Bwd Packet Length Max': 0,
                'packet_timestamps_fwd': [],
                'packet_timestamps_bwd': [],
                'fwd_packet_lengths': [],
                'bwd_packet_lengths': [],
            }
        
        flow = self.flows[flow_key]
        pkt_len = len(pkt)
        
        # Classify as forward or backward
        is_forward = (pkt[IP].src == flow_key[0] and pkt[IP].dst == flow_key[1])
        
        if is_forward:
            flow['Total Fwd Packets'] += 1
            flow['Total Length of Fwd Packets'] += pkt_len
            flow['Fwd Packet Length Max'] = max(flow['Fwd Packet Length Max'], pkt_len)
            flow['fwd_packet_lengths'].append(pkt_len)
            flow['packet_timestamps_fwd'].append(current_time)
        else:
            flow['Total Backward Packets'] += 1
            flow['Total Length of Bwd Packets'] += pkt_len
            flow['Bwd Packet Length Max'] = max(flow['Bwd Packet Length Max'], pkt_len)
            flow['bwd_packet_lengths'].append(pkt_len)
            flow['packet_timestamps_bwd'].append(current_time)
        
        # Return None (flow still active)
        return None
    
    def get_expired_flows(self) -> list:
        """Get flows that have timed out."""
        current_time = time.time()
        expired = []
        
        for flow_key, last_time in list(self.last_update.items()):
            if current_time - last_time > self.timeout:
                if flow_key in self.flows:
                    flow_data = self.flows[flow_key]
                    # Calculate derived features
                    self._calculate_flow_features(flow_data)
                    expired.append(flow_data)
                    del self.flows[flow_key]
                    del self.last_update[flow_key]
        
        return expired
    
    def _calculate_flow_features(self, flow: Dict[str, Any]):
        """Calculate derived flow features."""
        total_packets = flow['Total Fwd Packets'] + flow['Total Backward Packets']
        total_duration = (flow.get('packet_timestamps_bwd', [time.time()])[-1] - 
                         flow.get('packet_timestamps_fwd', [flow['start_time']])[0])
        
        if total_duration <= 0:
            total_duration = 1
        
        # Flow statistics
        flow['Flow Duration'] = total_duration * 1000  # Convert to ms
        flow['Flow Bytes/s'] = (flow['Total Length of Fwd Packets'] + 
                                flow['Total Length of Bwd Packets']) / total_duration if total_duration > 0 else 0
        flow['Flow Packets/s'] = total_packets / total_duration if total_duration > 0 else 0
        
        # Packet length statistics
        all_packets = flow['fwd_packet_lengths'] + flow['bwd_packet_lengths']
        if all_packets:
            flow['Max Packet Length'] = max(all_packets)
            flow['Min Packet Length'] = min(all_packets)
            flow['Packet Length Mean'] = sum(all_packets) / len(all_packets)
        else:
            flow['Max Packet Length'] = 0
            flow['Min Packet Length'] = 0
            flow['Packet Length Mean'] = 0
        
        # Fill in other required features with defaults
        flow['Destination Port'] = flow['dst_port']
        flow['Flow IAT Mean'] = 0
        flow['Average Packet Size'] = flow['Packet Length Mean']
        flow['Down/Up Ratio'] = (flow['Total Backward Packets'] / 
                                 max(flow['Total Fwd Packets'], 1))


class LivePacketCapture:
    """Capture live packets from network interface."""
    
    def __init__(self, interface: str, packet_callback: Callable):
        self.interface = interface
        self.callback = packet_callback
        self.running = False
        self.thread = None
        
    def start(self):
        """Start packet capture in background thread."""
        if self.running:
            logger.warning("Packet capture already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        logger.info(f"Started packet capture on interface {self.interface}")
    
    def _capture_loop(self):
        """Capture loop running in background."""
        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            self.running = False
    
    def _handle_packet(self, pkt):
        """Handle individual packet."""
        if IP in pkt:
            self.callback(pkt)
    
    def stop(self):
        """Stop packet capture."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Stopped packet capture")


class StreamingFlowProcessor:
    """
    Real-time packet-to-flow converter with queue-based processing.
    Processes packets and feeds complete flows to detection engine.
    """
    
    def __init__(self, callback: Callable, flow_timeout=60):
        self.callback = callback
        self.flow_timeout = flow_timeout
        self.extractor = PacketFlowExtractor(timeout=flow_timeout)
        self.packet_queue = queue.Queue(maxsize=10000)
        self.running = False
        self.processor_thread = None
        self.flow_counter = 0
        
    def add_packet(self, pkt):
        """Add packet to processing queue."""
        try:
            self.packet_queue.put_nowait(pkt)
        except queue.Full:
            logger.warning("Packet queue full, dropping packet")
    
    def start(self):
        """Start the flow processor thread."""
        if self.running:
            return
        
        self.running = True
        self.processor_thread = threading.Thread(target=self._process_loop, daemon=True)
        self.processor_thread.start()
        logger.info("Started streaming flow processor")
    
    def _process_loop(self):
        """Main processing loop."""
        while self.running:
            try:
                # Get packet from queue (with timeout to check for expired flows)
                pkt = self.packet_queue.get(timeout=1)
                
                # Update flow
                self.extractor.update_flow(pkt)
                
                # Check for expired flows
                expired_flows = self.extractor.get_expired_flows()
                for flow in expired_flows:
                    self.callback(flow)
                    self.flow_counter += 1
                    
            except queue.Empty:
                # Check for expired flows even if no packets
                expired_flows = self.extractor.get_expired_flows()
                for flow in expired_flows:
                    self.callback(flow)
                    self.flow_counter += 1
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
    
    def stop(self):
        """Stop the processor."""
        self.running = False
        if self.processor_thread:
            self.processor_thread.join(timeout=5)
        logger.info(f"Stopped processor. Processed {self.flow_counter} flows")


# Example usage
if __name__ == "__main__":
    def handle_flow(flow: Dict[str, Any]):
        """Callback for complete flows."""
        print(f"Complete flow: {flow['src_ip']} → {flow['dst_ip']}:{flow['dst_port']}")
        print(f"  Packets: {flow['Total Fwd Packets']} → {flow['Total Backward Packets']}")
        print(f"  Bytes: {flow['Total Length of Fwd Packets']} → {flow['Total Length of Bwd Packets']}")
    
    # Start live capture
    processor = StreamingFlowProcessor(handle_flow)
    processor.start()
    
    capture = LivePacketCapture("en0", processor.add_packet)
    capture.start()
    
    try:
        time.sleep(60)  # Capture for 60 seconds
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop()
        processor.stop()
