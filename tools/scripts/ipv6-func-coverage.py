#!/usr/bin/env python3
"""Fail unless every function in the IPv6 sources was executed.

An unreached function is either untested or dead code, and both are worth
failing the build over. Line coverage is deliberately not checked here: some
lines are defensive branches that need a malformed packet to reach, and
demanding 100% of those would push the tests towards contrivance.
"""
import json
import sys

TARGETS = ("src/wolfip6.c", "wolfip6.h")


def main(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    failed = False
    for name in TARGETS:
        entry = next((e for e in data.get("files", [])
                      if e.get("file", "").endswith(name)), None)
        if entry is None:
            print("ERROR: %s: no coverage data" % name)
            failed = True
            continue
        fns = entry.get("functions", [])
        if not fns:
            print("ERROR: %s: no function data" % name)
            failed = True
            continue
        covered = sum(1 for fn in fns if fn.get("execution_count", 0) > 0)
        print("%s: %d/%d functions (%.2f%%)"
              % (name, covered, len(fns), covered * 100.0 / len(fns)))
        for fn in fns:
            if fn.get("execution_count", 0) == 0:
                print("   uncovered:", fn.get("name"))
                failed = True
    if failed:
        print("ERROR: IPv6 function coverage must be 100%")
        return 1
    print("IPv6 function coverage: 100%")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1
                  else "build/coverage/ipv6.json"))
