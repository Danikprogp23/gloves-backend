import asyncio
import edge_tts
import sys

text = sys.argv[1]
voice = sys.argv[2]
output = sys.argv[3]

async def main():
    communicate = edge_tts.Communicate(
        text,
        voice
    )

    await communicate.save(output)

asyncio.run(main())