#!/usr/bin/env python3
"""Example test-pack runner for counterfactual symmetry evaluation."""

from __future__ import annotations

import json
import sys


def main() -> int:
    payload = {
        "result": "pass",
        "metrics": {
            "source-inclusion-asymmetry": 0.04,
            "claim-support-rate": 0.97,
        },
    }
    print(json.dumps(payload, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
