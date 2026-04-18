import json
import subprocess
import tempfile
from pathlib import Path


def run_command(command: list[str], input_data: str | None = None) -> list[str]:
    process = subprocess.run(
        command,
        input=input_data,
        capture_output=True,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(command)} :: {process.stderr.strip()}"
        )
    return [line.strip() for line in process.stdout.splitlines() if line.strip()]


def run_subfinder(domain: str) -> list[str]:
    return run_command(["subfinder", "-silent", "-d", domain])


def run_httpx(hosts: list[str]) -> set[str]:
    if not hosts:
        return set()
    input_data = "\n".join(hosts) + "\n"
    live = run_command(["httpx", "-silent"], input_data=input_data)
    return {url.split("://", 1)[-1].split("/", 1)[0] for url in live}


def run_gau(domain: str) -> list[str]:
    return run_command(["gau", "--subs", domain])


def run_nuclei(targets: list[str]) -> list[dict]:
    if not targets:
        return []
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("\n".join(targets))
        temp_path = f.name

    try:
        output = run_command(["nuclei", "-silent", "-jsonl", "-l", temp_path])
        findings: list[dict] = []
        for line in output:
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings
    finally:
        Path(temp_path).unlink(missing_ok=True)


def basic_security_headers(live_hosts: list[str]) -> list[dict]:
    findings = []
    for host in live_hosts:
        missing = []
        try:
            headers_lines = run_command(
                [
                    "httpx",
                    "-silent",
                    "-u",
                    f"https://{host}",
                    "-title",
                    "-status-code",
                    "-web-server",
                ]
            )
            if not headers_lines:
                missing.append("unable-to-fetch")
        except RuntimeError:
            missing.append("unreachable")
        if missing:
            findings.append(
                {
                    "template-id": "basic-header-check",
                    "info": {
                        "severity": "info",
                        "name": "Basic Header Reachability Check",
                    },
                    "matched-at": host,
                    "extracted-results": [", ".join(missing)],
                }
            )
    return findings
