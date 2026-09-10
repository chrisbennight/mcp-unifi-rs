#!/usr/bin/env python3
"""Check both container surfaces using fake credentials and no network access."""

import argparse
import os
import subprocess
import time
import uuid


def smoke(image: str, surface: str) -> None:
    config = {
        "UNIFI_MCP_SURFACE": surface,
        "UNIFI_MCP_GATEWAY_BEARER_CURRENT": "0123456789abcdef0123456789abcdef",
        "UNIFI_MCP_IDENTITY_JWKS_URL": "http://127.0.0.1:65533/jwks",
        "UNIFI_MCP_IDENTITY_ISSUER": "https://gateway.test",
        "UNIFI_MCP_IDENTITY_ACTOR": "gateway.test",
    }
    if surface == "network":
        config.update(
            UNIFI_MCP_CONTROLLER_URL="https://127.0.0.1:65532",
            UNIFI_MCP_CONTROLLER_API_KEY="smoke-controller-api-key",
            UNIFI_MCP_CONTROLLER_USERNAME="smoke-user",
            UNIFI_MCP_CONTROLLER_PASSWORD="smoke-controller-password",
        )
    elif surface == "protect":
        config.update(
            UNIFI_MCP_PROTECT_URL="https://127.0.0.1:65532",
            UNIFI_MCP_PROTECT_API_KEY="smoke-protect-api-key",
        )
    else:
        raise ValueError("unsupported smoke-test surface")
    name = f"mcp-unifi-smoke-{uuid.uuid4().hex}"
    command = [
        "docker", "create", "--name", name, "--network", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128",
    ]
    for variable in config:
        command.extend(["-e", variable])
    command.append(image)
    subprocess.run(
        command, env={**os.environ, **config}, check=True,
        stdout=subprocess.DEVNULL, timeout=30,
    )
    try:
        subprocess.run(
            ["docker", "start", name], check=True,
            stdout=subprocess.DEVNULL, timeout=10,
        )
        for _ in range(30):
            result = subprocess.run(
                ["docker", "exec", name, "/mcp-unifi-rs", "--healthcheck"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
            )
            if result.returncode == 0:
                return
            time.sleep(1)
        raise RuntimeError(f"{surface} container failed its liveness check")
    finally:
        subprocess.run(
            ["docker", "rm", "-f", name], check=True,
            stdout=subprocess.DEVNULL, timeout=10,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    args = parser.parse_args()
    for surface in ("network", "protect"):
        smoke(args.image, surface)
        print(f"{surface} image liveness passed")


if __name__ == "__main__":
    main()
