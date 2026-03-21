import asyncio
from pathlib import Path
from pentkit.payloads.corpus_builder import CorpusBuilder

async def main():
    corpus = CorpusBuilder()
    count = corpus._get_total_count()
    if count == 0:
        print("Corpus is empty. Building corpus...")
        stats = await corpus.build()
        print(f"Corpus built successfully: {stats.total_payloads} payloads.")
    else:
        print(f"Corpus already contains {count} payloads.")

if __name__ == "__main__":
    asyncio.run(main())
