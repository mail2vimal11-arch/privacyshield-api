"""
run_ingestion.py — Standalone script to populate Qdrant Cloud with
GDPR, NIST, and NVD knowledge bases.

Run from the privacyshield-api folder:
    QDRANT_URL=https://xxx.gcp.cloud.qdrant.io \
    QDRANT_API_KEY=your-key \
    python run_ingestion.py
"""

import os
import sys

# Must be run from privacyshield-api/
sys.path.insert(0, os.path.dirname(__file__))

# Set defaults if not in env (Railway will have these; local runner needs them)
if not os.environ.get("QDRANT_URL"):
    print("ERROR: Set QDRANT_URL env var before running.")
    print("  export QDRANT_URL=https://b68d7fbf-0d15-4fd9-acc4-0649fa97e18b.us-east4-0.gcp.cloud.qdrant.io")
    sys.exit(1)

if not os.environ.get("QDRANT_API_KEY"):
    print("ERROR: Set QDRANT_API_KEY env var before running.")
    sys.exit(1)

import asyncio
from app.dark_web_intelligence.slm.rag.ingestion import (
    ingest_gdpr,
    ingest_nist,
    ingest_nvd,
)
from app.dark_web_intelligence.slm.rag.vector_store import vector_store


async def main():
    print("\n=== Aletheos RAG Ingestion ===")
    print(f"Qdrant URL: {os.environ['QDRANT_URL']}")
    print()

    # Create collections
    print("→ Ensuring Qdrant collections exist...")
    vector_store.ensure_collections()
    print()

    # Ingest GDPR
    print("→ Ingesting GDPR (EUR-Lex)...")
    try:
        gdpr_count = await ingest_gdpr()
        print(f"  ✅ GDPR: {gdpr_count} chunks ingested")
    except Exception as e:
        print(f"  ⚠️  GDPR failed: {e}")

    print()

    # Ingest NIST
    print("→ Ingesting NIST CSF...")
    try:
        nist_count = await ingest_nist()
        print(f"  ✅ NIST: {nist_count} chunks ingested")
    except Exception as e:
        print(f"  ⚠️  NIST failed: {e}")

    print()

    # Ingest NVD CVEs
    print("→ Ingesting NVD CVE feed (recent)...")
    try:
        nvd_count = await ingest_nvd()
        print(f"  ✅ NVD: {nvd_count} CVEs ingested")
    except Exception as e:
        print(f"  ⚠️  NVD failed: {e}")

    print()
    print("=== Ingestion complete ===")
    print()

    # Show counts
    for col in ["aletheos_gdpr", "aletheos_nist", "aletheos_nvd"]:
        try:
            count = vector_store.collection_count(col)
            print(f"  {col}: {count} vectors")
        except Exception as e:
            print(f"  {col}: error — {e}")


if __name__ == "__main__":
    asyncio.run(main())
