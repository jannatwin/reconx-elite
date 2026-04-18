"""Prometheus metrics for ReconX Elite."""

from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry

# Create registry
registry = CollectorRegistry()

# Scan metrics
scan_initiated = Counter(
    "scan_initiated_total",
    "Total number of scans initiated",
    ["target", "scan_type"],
    registry=registry,
)

scan_completed = Counter(
    "scan_completed_total",
    "Total number of scans completed",
    ["target", "scan_type"],
    registry=registry,
)

scan_failed = Counter(
    "scan_failed_total",
    "Total number of scans that failed",
    ["target", "error_type"],
    registry=registry,
)

scan_duration = Histogram(
    "scan_duration_seconds",
    "Scan execution time in seconds",
    ["target", "scan_type"],
    buckets=(30, 60, 300, 900, 1800, 3600),
    registry=registry,
)

# Vulnerability metrics
vulnerabilities_found = Counter(
    "vulnerabilities_found_total",
    "Total vulnerabilities found",
    ["severity", "type"],
    registry=registry,
)

vulnerability_severity_gauge = Gauge(
    "vulnerabilities_current",
    "Current vulnerabilities by severity",
    ["severity"],
    registry=registry,
)

# AI metrics
ai_api_calls = Counter(
    "ai_api_calls_total",
    "Total AI API calls",
    ["model", "task", "status"],
    registry=registry,
)

ai_api_latency = Histogram(
    "ai_api_latency_seconds",
    "AI API latency in seconds",
    ["model", "task"],
    buckets=(0.5, 1, 2, 5, 10, 30),
    registry=registry,
)

ai_api_errors = Counter(
    "ai_api_errors_total",
    "Total AI API errors",
    ["model", "error_type"],
    registry=registry,
)

ai_tokens_used = Counter(
    "ai_tokens_used_total",
    "Total tokens used in AI calls",
    ["model", "type"],  # type: input or output
    registry=registry,
)

# Active operations
active_scans = Gauge("active_scans", "Currently running scans", registry=registry)

active_vulnerability_modules = Gauge(
    "active_vulnerability_modules",
    "Currently running vulnerability modules",
    ["module"],
    registry=registry,
)

# Database metrics
database_query_time = Histogram(
    "database_query_time_seconds",
    "Database query execution time",
    ["operation"],  # query, insert, update, delete
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0),
    registry=registry,
)

database_connection_pool_usage = Gauge(
    "database_connection_pool_usage",
    "Current database connection pool usage",
    registry=registry,
)

# Cache metrics
cache_hits = Counter(
    "cache_hits_total", "Total cache hits", ["cache_type"], registry=registry
)

cache_misses = Counter(
    "cache_misses_total", "Total cache misses", ["cache_type"], registry=registry
)

# Phase metrics
phase_execution_time = Histogram(
    "phase_execution_time_seconds",
    "Time to execute each phase",
    ["phase"],
    buckets=(10, 30, 60, 300, 600, 1800),
    registry=registry,
)

phase_findings = Counter(
    "phase_findings_total", "Findings per phase", ["phase"], registry=registry
)

# HTTP metrics
http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
    registry=registry,
)

http_request_duration = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration",
    ["method", "endpoint"],
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0),
    registry=registry,
)

# System health
system_health = Gauge(
    "system_health", "Overall system health (1=healthy, 0=unhealthy)", registry=registry
)

worker_queue_size = Gauge(
    "worker_queue_size", "Number of tasks in worker queue", ["queue"], registry=registry
)


class MetricsCollector:
    """Helper class for recording metrics."""

    @staticmethod
    def record_scan_start(target: str, scan_type: str) -> None:
        """Record scan initiation."""
        scan_initiated.labels(target=target, scan_type=scan_type).inc()
        active_scans.inc()

    @staticmethod
    def record_scan_complete(target: str, scan_type: str, duration: float) -> None:
        """Record scan completion."""
        scan_completed.labels(target=target, scan_type=scan_type).inc()
        scan_duration.labels(target=target, scan_type=scan_type).observe(duration)
        active_scans.dec()

    @staticmethod
    def record_scan_failure(target: str, error_type: str) -> None:
        """Record scan failure."""
        scan_failed.labels(target=target, error_type=error_type).inc()
        active_scans.dec()

    @staticmethod
    def record_vulnerability(severity: str, vuln_type: str) -> None:
        """Record vulnerability discovery."""
        vulnerabilities_found.labels(severity=severity, type=vuln_type).inc()

    @staticmethod
    def record_ai_call(model: str, task: str, latency: float, status: str) -> None:
        """Record AI API call."""
        ai_api_calls.labels(model=model, task=task, status=status).inc()
        ai_api_latency.labels(model=model, task=task).observe(latency)

    @staticmethod
    def record_ai_error(model: str, error_type: str) -> None:
        """Record AI API error."""
        ai_api_errors.labels(model=model, error_type=error_type).inc()

    @staticmethod
    def record_tokens_used(model: str, input_tokens: int, output_tokens: int) -> None:
        """Record token usage."""
        ai_tokens_used.labels(model=model, type="input").inc(input_tokens)
        ai_tokens_used.labels(model=model, type="output").inc(output_tokens)

    @staticmethod
    def record_phase_execution(phase: str, duration: float, findings: int) -> None:
        """Record phase execution metrics."""
        phase_execution_time.labels(phase=phase).observe(duration)
        phase_findings.labels(phase=phase).inc(findings)

    @staticmethod
    def record_http_request(
        method: str, endpoint: str, status: int, duration: float
    ) -> None:
        """Record HTTP request metrics."""
        http_requests_total.labels(
            method=method, endpoint=endpoint, status=status
        ).inc()
        http_request_duration.labels(method=method, endpoint=endpoint).observe(duration)

    @staticmethod
    def set_system_health(healthy: bool) -> None:
        """Set system health status."""
        system_health.set(1 if healthy else 0)

    @staticmethod
    def update_cache_hit(cache_type: str) -> None:
        """Record cache hit."""
        cache_hits.labels(cache_type=cache_type).inc()

    @staticmethod
    def update_cache_miss(cache_type: str) -> None:
        """Record cache miss."""
        cache_misses.labels(cache_type=cache_type).inc()
