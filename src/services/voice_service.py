import subprocess
import logging
import platform
from src import config

logger = logging.getLogger(__name__)

class VoiceAssistant:
    """
    A voice-driven security assistant that provides high-tech audible alerts
    modeled after custom AI assistants (e.g., Jarvis or Friday).
    """
    
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.os_type = platform.system()

    def speak(self, text: str, voice: str = None):
        """
        Synthesizes speech from text using system utilities.
        Supports custom high-quality macOS voices.
        """
        if not self.enabled:
            return

        try:
            if self.os_type == "Darwin":  # macOS
                if voice:
                    subprocess.Popen(["say", "-v", voice, text])
                else:
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
        Provides a structured high-fidelity alert based on the active persona.
        """
        persona = getattr(config, "VOICE_PERSONA", "jarvis")
        
        voice = None
        if self.os_type == "Darwin":
            if persona == "jarvis":
                voice = "Daniel"  # Iconic UK English male voice (sounds like Jarvis)
            elif persona == "friday":
                voice = "Samantha"  # High-tech US English female voice (sounds like Friday)

        if risk_score >= 8.0:
            if persona == "jarvis":
                message = f"Sir, I have detected a critical threat anomaly. A {threat_type} attack has been initiated from source IP {src_ip}. The risk assessment is extremely high at {risk_score} out of 10. I highly advise immediate isolation of this host."
            elif persona == "friday":
                message = f"Warning! Critical threat active. {threat_type} pattern detected from {src_ip}. Risk factor is high at {risk_score}. Quarantine protocol is highly recommended."
            else:
                message = f"Security Alert. Critical {threat_type} detected from {src_ip}. Risk score {risk_score}."
            
            self.speak(message, voice=voice)
            
        elif risk_score >= 6.0:
            if persona == "jarvis":
                message = f"Excuse me, sir. I have detected suspicious network activity. A suspected {threat_type} is originating from {src_ip}."
            elif persona == "friday":
                message = f"Heads up. Suspected {threat_type} activity detected from {src_ip}. Monitoring the flow."
            else:
                message = f"Warning. Suspected {threat_type} from {src_ip}."
                
            self.speak(message, voice=voice)

# Global instance
voice_assistant = VoiceAssistant(enabled=config.ENABLE_BACKEND_VOICE)
