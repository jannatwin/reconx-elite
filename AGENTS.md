# AGENTS.md

This file provides guidance to the AI orchestrator and task-specific models when working with code in this repository.

## Project Overview

ReconX-Elite is a multi-model AI-powered bug bounty hunting system built around a wildcard domain assessment workflow. It automates the full lifecycle of a bug bounty engagement, from reconnaissance to vulnerability discovery and reporting.

## AI Model Architecture & Roles

ReconX-Elite uses a sophisticated multi-model architecture where each task is routed to the most capable model based on capability, context length, and speed requirements.

### Orchestration
- **Nemotron 3 Nano 30B A3B**: The primary routing agent and decision-maker. It directs tasks through the ten-phase workflow and handles escalation logic.

### Task-Specific Agents
- **Llama 3.3 70B**: Primary analysis, IDOR test generation, severity rating, and standard report generation.
- **Nemotron 3 Super**: Deep chain-of-thought reasoning, JWT attack analysis, and SSRF escalation logic.
- **Qwen3 Coder 480B**: All code generation, payload creation, and complex JavaScript file analysis.
- **GLM 4.5 Air**: Fast classification of subdomains and host triage.
- **Gemma 4 26B A4B**: Structured JSON extraction from raw tool output.
- **Gemma 4 31B**: Misconfiguration and HTTP header analysis.
- **MiniMax M2.5**: Long-context JavaScript file analysis (optimized for large file ingestion).
- **gpt-oss-120b**: High and Critical severity reports and executive summaries.
- **gpt-oss-20b**: Low and Medium severity report drafting.

## Recon Pipeline Workflow

The recon pipeline is designed for comprehensive coverage and deduplication.

1.  **Subdomain Enumeration**: Uses `subfinder`, `sublist3r`, `findomain`, `crt.sh`, `massdns`, and `gobuster`. Results are consolidated into `all_subs.txt`.
2.  **Host Discovery**: Uses `httpx` and `httprobe` to identify live services.
3.  **Infrastructure Mapping**: `nmap` and `masscan` for port discovery; `gowitness` for visual screenshots.
4.  **URL Discovery**: `gau`, `waybackurls`, `katana`, and `hakrawler` are used to build a comprehensive endpoint map.
5.  **Parameter Extraction**: `params.txt` contains all endpoints with parameters for targeted testing.
6.  **JS Intelligence**: Automated analysis using `SecretFinder`, `LinkFinder`, and `trufflehog`.

## Vulnerability Pipeline Workflow

1.  **Takeover Detection**: `subjack` and `nuclei`.
2.  **Web Vulnerabilities**: XSS (`kxss`, `dalfox`), SQLi (`sqlmap`, `ghauri`), SSRF (`interactsh`).
3.  **Cloud & Config**: AWS/Cloud bucket enumeration (`cloud_enum`), security header audits, and sensitive file discovery.
4.  **Template-Based Scanning**: Comprehensive `nuclei` template execution.

## Dashboard Capabilities

- **Progress Tracking**: Pipeline progress bar and live agent logs.
- **Findings Management**: Severity-badged cards and statistical grids.
- **Model Activity**: Real-time grid showing which AI model is currently active and its assigned task.
