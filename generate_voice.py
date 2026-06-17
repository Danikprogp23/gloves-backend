import os
import sys
import azure.cognitiveservices.speech as speechsdk

text = sys.argv[1]
voice = sys.argv[2]
output = sys.argv[3]

speech_key = os.getenv("AZURE_SPEECH_KEY")
endpoint = os.getenv("AZURE_SPEECH_ENDPOINT")

speech_config = speechsdk.SpeechConfig(
    subscription=speech_key,
    endpoint=endpoint
)

speech_config.speech_synthesis_voice_name = voice

audio_config = speechsdk.audio.AudioOutputConfig(
    filename=output
)

synthesizer = speechsdk.SpeechSynthesizer(
    speech_config=speech_config,
    audio_config=audio_config
)

result = synthesizer.speak_text_async(text).get()

if result.reason != speechsdk.ResultReason.SynthesizingAudioCompleted:
    raise Exception("Speech synthesis failed")