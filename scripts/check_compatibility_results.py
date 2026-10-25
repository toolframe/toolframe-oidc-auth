"""Require complete runtime/operator test execution in compatibility lanes."""

import argparse
import json
from pathlib import Path
from xml.etree import ElementTree


def check_results(path, mode):
    cases = ElementTree.parse(path).getroot().findall(".//testcase")
    operator = [
        case
        for case in cases
        if case.get("classname", "").rsplit(".", 1)[-1]
        == "test_registration_maintenance"
    ]
    skipped = [case for case in cases if case.find("skipped") is not None]
    if any(
        case.find(tag) is not None for case in cases for tag in ("failure", "error")
    ):
        raise ValueError("Compatibility tests contain failures or errors")
    if mode == "runtime":
        if len(cases) != 34 or len(operator) != 12 or skipped != operator:
            raise ValueError(
                "Runtime lanes must execute 22 cases and skip only the 12 Core-only cases"
            )
    elif len(cases) != 12 or len(operator) != 12 or skipped:
        raise ValueError(
            "Operator lanes must execute all 12 Core-only cases with zero skips"
        )
    return {
        "mode": mode,
        "tests": len(cases),
        "passed": len(cases) - len(skipped),
        "skipped": len(skipped),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("runtime", "operator"))
    parser.add_argument("--junit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = check_results(args.junit, args.mode)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
