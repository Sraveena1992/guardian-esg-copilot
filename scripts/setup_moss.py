"""Create or refresh the Guardian policy index in Moss.

Usage:
    python -m scripts.setup_moss
"""

import asyncio
import json
import os
from pathlib import Path

from moss import MossClient, MutationOptions


ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = ROOT / "policies" / "guardian_esg_policies.json"


async def main() -> None:
    project_id = os.environ["MOSS_PROJECT_ID"]
    project_key = os.environ["MOSS_PROJECT_KEY"]
    index_name = os.getenv("MOSS_INDEX_NAME", "guardian_esg_policies")

    client = MossClient(project_id, project_key)

    with POLICY_FILE.open("r", encoding="utf-8") as f:
        documents = json.load(f)

    try:
        await client.get_index(index_name)
        await client.add_docs(
            index_name,
            documents,
            MutationOptions(upsert=True),
        )
        print(f"Updated Moss index: {index_name}")
    except Exception:
        await client.create_index(index_name, documents)
        print(f"Created Moss index: {index_name}")


if __name__ == "__main__":
    asyncio.run(main())
