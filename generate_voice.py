import asyncio
import edge_tts

async def main():
    communicate = edge_tts.Communicate(
        "Жақсы көремін",
        "kk-KZ-AigulNeural"
    )

    await communicate.save("love.mp3")

asyncio.run(main())