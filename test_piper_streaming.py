import os
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
import numpy as np
import sounddevice as sd
from piper.voice import PiperVoice

# Add Medusa to path if needed (using current .venv)
model_path = r"c:\Users\ajst1\Downloads\Medusa\medusa\engine\modules\ai\voices\en_GB-aru-medium.onnx"
voice = PiperVoice.load(model_path)

def stream_speak(text: str):
    # Get samplerate from the config
    # Piper models usually are 22050Hz or 16000Hz or 44100Hz
    # The config_path is model_path + ".json"
    import json
    with open(model_path + ".json", "r") as f:
        config = json.load(f)
    samplerate = config.get("audio", {}).get("sample_rate", 22050)
    
    print(f"Streaming at {samplerate}Hz...")
    
    # Initialize sounddevice stream
    with sd.RawOutputStream(samplerate=samplerate, blocksize=1024, channels=1, dtype='int16') as stream:
        for audio_chunk in voice.synthesize(text):
            # audio_chunk.audio_int16_bytes is raw PCM
            stream.write(audio_chunk.audio_int16_bytes)

if __name__ == "__main__":
    stream_speak("Hello. This is a zero delay test using Piper and sounddevice.")
