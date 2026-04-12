try:
    from prometheus_client import Counter, Histogram, Gauge
except ModuleNotFoundError:  # pragma: no cover - local fallback
    class _NoopMetric:
        def labels(self, **kwargs):  # noqa: ARG002
            return self

        def inc(self, *args, **kwargs):  # noqa: ARG002
            return None

        def observe(self, *args, **kwargs):  # noqa: ARG002
            return None

        def set(self, *args, **kwargs):  # noqa: ARG002
            return None

    def Counter(*args, **kwargs):  # type: ignore[misc] # noqa: N802, ARG001
        return _NoopMetric()

    def Histogram(*args, **kwargs):  # type: ignore[misc] # noqa: N802, ARG001
        return _NoopMetric()

    def Gauge(*args, **kwargs):  # type: ignore[misc] # noqa: N802, ARG001
        return _NoopMetric()

http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path"],
)

db_pool_connections = Gauge(
    "db_pool_connections",
    "Active database pool connections",
)
