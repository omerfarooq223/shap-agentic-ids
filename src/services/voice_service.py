import subprocess
import logging
import platform

logger = logging.getLogger(__name__)

class VoiceAssistant:
    """
    A simple voice-driven security assistant that provides audible alerts
    for high-risk network anomalies.
    """
    
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.os_type = platform.system()

    def speak(self, text: str):
        """
        Synthesizes speech from text using system utilities.
        """
        if not self.enabled:
            return

        try:
            if self.os_type == "Darwin":  # macOS
                subprocess.Popen(["say", text])
            elif self.os_type == "Linux":
                # Assuming espeak is installed on Linux
                subprocess.Popen(["espeak", text])
            else:
                logger.warning(f"Voice assistant not supported on {self.os_type}")
        except Exception as e:
            logger.error(f"Failed to execute voice synthesis: {e}")

    def announce_threat(self, threat_type: str, risk_score: float, src_ip: str):
        """
        Provides a structured audible alert for a detected threat.
        """
        if risk_score >= 8.0:
            message = f"Security Alert. Critical {threat_type} detected from {src_ip}. Risk score {risk_score}. Immediate investigation recommended."
            self.speak(message)
        elif risk_score >= 6.0:
            message = f"Warning. Suspected {threat_type} from {src_ip}."
            self.speak(message)

# Global instance
voice_assistant = VoiceAssistant(enabled=True)
