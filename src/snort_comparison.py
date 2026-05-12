#!/usr/bin/env python3
"""
Real Snort/Suricata Integration for IDS Comparison

Compares Agentic IDS detection results with:
1. Real Snort alerting
2. Real Suricata alerting
3. Signature-based detection

Requires:
- Snort (brew install snort)
- Suricata (brew install suricata)
- tcpdump for PCAP file creation
"""

import subprocess
import json
import os
import re
import logging
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


class SnortIntegration:
    """Run Snort IDS and capture alerts."""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.alerts = []
    
    def check_snort_installed(self) -> bool:
        """Check if Snort is installed."""
        try:
            result = subprocess.run(['snort', '--version'], 
                                  capture_output=True, text=True)
            logger.info(f"Snort version: {result.stdout.strip()}")
            return True
        except FileNotFoundError:
            logger.warning("Snort not found. Install with: brew install snort")
            return False
    
    def run_snort(self, output_dir="/tmp/snort_alerts") -> List[Dict[str, Any]]:
        """
        Run Snort on PCAP file and parse alerts.
        """
        if not self.check_snort_installed():
            logger.warning("Snort not installed, skipping comparison")
            return []
        
        os.makedirs(output_dir, exist_ok=True)
        alert_file = os.path.join(output_dir, "alert")
        
        try:
            # Run Snort with alert generation
            cmd = [
                'snort',
                '-r', self.pcap_file,
                '-A', 'full',
                '-l', output_dir,
                '-q',  # Quiet mode
                '--no-promisc'
            ]
            
            logger.info(f"Running Snort: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            logger.info(f"Snort output: {result.stdout}")
            
            # Parse alerts from file
            if os.path.exists(alert_file):
                self.alerts = self._parse_snort_alerts(alert_file)
                logger.info(f"Snort detected {len(self.alerts)} alerts")
            
            return self.alerts
            
        except subprocess.TimeoutExpired:
            logger.error("Snort execution timeout")
            return []
        except Exception as e:
            logger.error(f"Snort execution error: {e}")
            return []
    
    def _parse_snort_alerts(self, alert_file: str) -> List[Dict[str, Any]]:
        """Parse Snort alert file."""
        alerts = []
        
        try:
            with open(alert_file, 'r') as f:
                content = f.read()
                
            # Parse alert lines
            alert_pattern = r'(\d+/\d+/\d+ \d+:\d+:\d+\.\d+).+?\{([A-Z_]+)\}.+?(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)'
            
            for match in re.finditer(alert_pattern, content):
                alert = {
                    'timestamp': match.group(1),
                    'classification': match.group(2),
                    'src_ip': match.group(3),
                    'src_port': match.group(4),
                    'dst_ip': match.group(5),
                    'dst_port': match.group(6),
                }
                alerts.append(alert)
        except Exception as e:
            logger.error(f"Error parsing Snort alerts: {e}")
        
        return alerts


class SuricataIntegration:
    """Run Suricata IDS and capture alerts."""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.alerts = []
    
    def check_suricata_installed(self) -> bool:
        """Check if Suricata is installed."""
        try:
            result = subprocess.run(['suricata', '--version'], 
                                  capture_output=True, text=True)
            logger.info(f"Suricata version: {result.stdout.strip()}")
            return True
        except FileNotFoundError:
            logger.warning("Suricata not found. Install with: brew install suricata")
            return False
    
    def run_suricata(self, output_dir="/tmp/suricata_alerts") -> List[Dict[str, Any]]:
        """
        Run Suricata on PCAP file and parse alerts.
        """
        if not self.check_suricata_installed():
            logger.warning("Suricata not installed, skipping comparison")
            return []
        
        os.makedirs(output_dir, exist_ok=True)
        eve_file = os.path.join(output_dir, "eve.json")
        
        try:
            # Run Suricata
            cmd = [
                'suricata',
                '-r', self.pcap_file,
                '-l', output_dir,
                '-q'  # Quiet mode
            ]
            
            logger.info(f"Running Suricata: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            logger.info(f"Suricata output: {result.stdout}")
            
            # Parse alerts from JSON
            if os.path.exists(eve_file):
                self.alerts = self._parse_suricata_alerts(eve_file)
                logger.info(f"Suricata detected {len(self.alerts)} alerts")
            
            return self.alerts
            
        except subprocess.TimeoutExpired:
            logger.error("Suricata execution timeout")
            return []
        except Exception as e:
            logger.error(f"Suricata execution error: {e}")
            return []
    
    def _parse_suricata_alerts(self, eve_file: str) -> List[Dict[str, Any]]:
        """Parse Suricata EVE JSON output."""
        alerts = []
        
        try:
            with open(eve_file, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        
                        # Filter for alert events only
                        if event.get('event_type') == 'alert':
                            alert = {
                                'timestamp': event.get('timestamp'),
                                'alert': event.get('alert', {}).get('action'),
                                'src_ip': event.get('src_ip'),
                                'src_port': event.get('src_port'),
                                'dst_ip': event.get('dest_ip'),
                                'dst_port': event.get('dest_port'),
                                'signature': event.get('alert', {}).get('signature'),
                            }
                            alerts.append(alert)
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.error(f"Error parsing Suricata alerts: {e}")
        
        return alerts


class IDSComparison:
    """Compare Agentic IDS, Snort, and Suricata detection results."""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.snort = SnortIntegration(pcap_file)
        self.suricata = SuricataIntegration(pcap_file)
    
    def run_comparison(self) -> Dict[str, Any]:
        """Run all IDS systems and compare."""
        logger.info("=" * 80)
        logger.info("IDS COMPARISON: Agentic IDS vs Snort vs Suricata")
        logger.info("=" * 80)
        
        snort_alerts = self.snort.run_snort()
        suricata_alerts = self.suricata.run_suricata()
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'pcap_file': self.pcap_file,
            'snort': {
                'installed': self.snort.check_snort_installed(),
                'alerts_count': len(snort_alerts),
                'alerts': snort_alerts[:10]  # First 10
            },
            'suricata': {
                'installed': self.suricata.check_suricata_installed(),
                'alerts_count': len(suricata_alerts),
                'alerts': suricata_alerts[:10]  # First 10
            },
            'comparison': self._analyze_differences(snort_alerts, suricata_alerts)
        }
        
        return results
    
    def _analyze_differences(self, snort_alerts: List, suricata_alerts: List) -> Dict[str, Any]:
        """Analyze detection differences."""
        snort_flows = set((a['src_ip'], a['dst_ip']) for a in snort_alerts)
        suricata_flows = set((a['src_ip'], a['dst_ip']) for a in suricata_alerts)
        
        return {
            'snort_only': len(snort_flows - suricata_flows),
            'suricata_only': len(suricata_flows - snort_flows),
            'both_detected': len(snort_flows & suricata_flows),
            'total_unique_flows': len(snort_flows | suricata_flows),
        }


if __name__ == "__main__":
    # Example: Compare on captured PCAP
    pcap_path = "captured_traffic.pcap"
    
    if os.path.exists(pcap_path):
        comparison = IDSComparison(pcap_path)
        results = comparison.run_comparison()
        
        print(json.dumps(results, indent=2))
    else:
        print(f"PCAP file not found: {pcap_path}")
        print("\nTo create a PCAP file, run:")
        print("  tcpdump -i en0 -w captured_traffic.pcap")
