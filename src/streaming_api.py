#!/usr/bin/env python3
"""
Streaming IDS Endpoint for Real-Time Packet Processing

Adds /stream endpoint to Flask for continuous packet-to-detection pipeline.
Routes:
  - POST /stream/start - Start live packet capture on interface
  - POST /stream/stop - Stop capture
  - GET /stream/status - Stream status
  - POST /stream/packet - Add packet to processing queue
  - GET /stream/stats - Processing statistics
"""

from flask import Blueprint, request, jsonify, Response
import logging
from src import config
from src.packet_capture import StreamingFlowProcessor, LivePacketCapture
import json

logger = logging.getLogger(__name__)

# Global streaming state
streaming_state = {
    'running': False,
    'processor': None,
    'capture': None,
    'flows_processed': 0,
    'anomalies_detected': 0,
    'start_time': None,
}


def create_streaming_blueprint(detect_callback):
    """
    Create Flask blueprint for streaming endpoints.
    
    Args:
        detect_callback: Function to call for each complete flow (e.g., ML detection)
    """
    streaming_bp = Blueprint('streaming', __name__, url_prefix='/stream')
    
    def flow_handler(flow):
        """Handle complete flow: run detection and update stats."""
        try:
            result = detect_callback(flow)
            streaming_state['flows_processed'] += 1
            
            if result.get('anomaly'):
                streaming_state['anomalies_detected'] += 1
                
                # Log anomaly
                logger.warning(f"[STREAMING] Anomaly detected: {flow['src_ip']} → {flow['dst_ip']}")
                logger.warning(f"[STREAMING] Threat: {result.get('threat_type')}, Risk: {result.get('risk_score')}")
                
        except Exception as e:
            logger.error(f"Error processing flow: {e}")
    
    @streaming_bp.route('/start', methods=['POST'])
    def start_streaming():
        """Start live packet capture on network interface."""
        if streaming_state['running']:
            return jsonify({'error': 'Streaming already running'}), 400
        
        data = request.get_json() or {}
        interface = data.get('interface', config.DEFAULT_INTERFACE)
        
        try:
            import time
            
            # Create processor
            streaming_state['processor'] = StreamingFlowProcessor(flow_handler)
            streaming_state['processor'].start()
            
            # Create and start capture
            streaming_state['capture'] = LivePacketCapture(interface, 
                                                           streaming_state['processor'].add_packet)
            streaming_state['capture'].start()
            
            streaming_state['running'] = True
            streaming_state['start_time'] = time.time()
            
            logger.info(f"Started packet capture on {interface}")
            
            return jsonify({
                'status': 'started',
                'interface': interface,
                'message': f'Capturing packets on {interface}'
            }), 200
            
        except PermissionError:
            logger.error("Permission denied for packet capture. Run with sudo.")
            return jsonify({
                'error': 'Permission denied',
                'message': 'Packet capture requires elevated privileges (sudo)'
            }), 403
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            return jsonify({'error': str(e)}), 500
    
    @streaming_bp.route('/stop', methods=['POST'])
    def stop_streaming():
        """Stop packet capture."""
        if not streaming_state['running']:
            return jsonify({'error': 'Streaming not running'}), 400
        
        try:
            streaming_state['capture'].stop()
            streaming_state['processor'].stop()
            streaming_state['running'] = False
            
            logger.info("Stopped packet capture")
            
            return jsonify({
                'status': 'stopped',
                'flows_processed': streaming_state['flows_processed'],
                'anomalies_detected': streaming_state['anomalies_detected']
            }), 200
            
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")
            return jsonify({'error': str(e)}), 500
    
    @streaming_bp.route('/status', methods=['GET'])
    def streaming_status():
        """Get current streaming status."""
        import time
        
        status = {
            'running': streaming_state['running'],
            'flows_processed': streaming_state['flows_processed'],
            'anomalies_detected': streaming_state['anomalies_detected'],
        }
        
        if streaming_state['running'] and streaming_state['start_time']:
            elapsed = time.time() - streaming_state['start_time']
            status['elapsed_seconds'] = elapsed
            status['flows_per_second'] = (streaming_state['flows_processed'] / elapsed 
                                         if elapsed > 0 else 0)
        
        return jsonify(status), 200
    
    @streaming_bp.route('/stats', methods=['GET'])
    def streaming_stats():
        """Get detailed streaming statistics."""
        import time
        
        stats = {
            'running': streaming_state['running'],
            'total_flows_processed': streaming_state['flows_processed'],
            'total_anomalies': streaming_state['anomalies_detected'],
            'anomaly_rate': (streaming_state['anomalies_detected'] / 
                           max(streaming_state['flows_processed'], 1) * 100),
        }
        
        if streaming_state['running'] and streaming_state['start_time']:
            elapsed = time.time() - streaming_state['start_time']
            stats['runtime_seconds'] = elapsed
            stats['flows_per_second'] = (streaming_state['flows_processed'] / elapsed 
                                        if elapsed > 0 else 0)
        
        return jsonify(stats), 200
    
    return streaming_bp
