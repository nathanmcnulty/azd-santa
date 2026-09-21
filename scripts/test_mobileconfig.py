#!/usr/bin/env python3
"""Offline semantic validation for generated Apple configuration profiles."""

from __future__ import annotations

import plistlib
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test_mobileconfig.py <profile-directory>", file=sys.stderr)
        return 2

    profile_dir = Path(sys.argv[1])
    files = sorted(profile_dir.glob("*.mobileconfig"))
    if not files:
        raise ValueError(f"no mobileconfig files found in {profile_dir}")

    identifiers: set[str] = set()
    for path in files:
        with path.open("rb") as stream:
            profile = plistlib.load(stream)
        if profile.get("PayloadType") != "Configuration":
            raise ValueError(f"{path.name}: top-level PayloadType must be Configuration")
        for required in ("PayloadUUID", "PayloadIdentifier", "PayloadContent"):
            if required not in profile:
                raise ValueError(f"{path.name}: missing {required}")
        for payload in profile["PayloadContent"]:
            for required in ("PayloadType", "PayloadIdentifier", "PayloadUUID"):
                if required not in payload:
                    raise ValueError(f"{path.name}: nested payload missing {required}")
            identifier = payload["PayloadIdentifier"]
            if identifier in identifiers:
                raise ValueError(f"duplicate nested PayloadIdentifier: {identifier}")
            identifiers.add(identifier)

    config_path = profile_dir / "40-configuration.mobileconfig"
    with config_path.open("rb") as stream:
        config = plistlib.load(stream)["PayloadContent"][0]
    if config.get("ClientMode") != 1:
        raise ValueError("Santa configuration must use ClientMode 1 (MONITOR)")
    if "SyncBaseURL" in config:
        raise ValueError("deployment-only baseline must not require a sync server")
    allowed_keys = {
        "PayloadType", "PayloadVersion", "PayloadIdentifier", "PayloadUUID", "ClientMode",
        "EnableSilentMode", "ModeNotificationMonitor", "StaticRules",
    }
    unknown_keys = set(config) - allowed_keys
    if unknown_keys:
        raise ValueError(f"Santa configuration contains unreviewed keys: {sorted(unknown_keys)}")
    if any(rule.get("rule_type") != "SIGNINGID" for rule in config.get("StaticRules", [])):
        raise ValueError("bootstrap rules must use narrow SIGNINGID rules")
    print(f"Validated {len(files)} semantic plist files in MONITOR mode.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
