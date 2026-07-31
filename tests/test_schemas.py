from __future__ import annotations

import json
from pathlib import Path


def test_every_public_json_contract_has_a_strict_schema() -> None:
    schema_root = Path(__file__).parents[1] / "schemas"
    expected = {
        "corpus-gate-v1.schema.json",
        "finding-v1.schema.json",
        "importer-catalog-v1.schema.json",
        "replay-v1.schema.json",
        "research-results-v1.schema.json",
    }

    assert {path.name for path in schema_root.glob("*.schema.json")} == expected
    for path in schema_root.glob("*.schema.json"):
        payload = json.loads(path.read_bytes())
        assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert payload["additionalProperties"] is False
