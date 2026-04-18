import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class ToolExecutionResult:
    tool: str
    command: list[str]
    status: str
    attempts: int
    started_at: datetime
    ended_at: datetime
    duration_ms: int
    return_code: int | None
    stdout: str
    stderr: str
    error: str | None = None

    def to_json(self) -> dict:
        return {
            "tool": self.tool,
            "command": self.command,
            "status": self.status,
            "attempts": self.attempts,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "duration_ms": self.duration_ms,
            "return_code": self.return_code,
            "error": self.error,
        }


def execute_with_retry(
    tool: str,
    command: list[str],
    *,
    stdin_payload: str | None = None,
    timeout_seconds: int = 180,
    max_retries: int = 2,
) -> ToolExecutionResult:
    attempts_total = max_retries + 1
    last_result: ToolExecutionResult | None = None

    for attempt in range(1, attempts_total + 1):
        started_at = datetime.now(timezone.utc)
        try:
            proc = subprocess.run(
                command,
                input=stdin_payload,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds,
            )
            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)
            status = "success" if proc.returncode == 0 else "failed"
            result = ToolExecutionResult(
                tool=tool,
                command=command,
                status=status,
                attempts=attempt,
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                return_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                error=(
                    None if proc.returncode == 0 else f"non_zero_exit:{proc.returncode}"
                ),
            )
        except subprocess.TimeoutExpired as exc:
            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)
            result = ToolExecutionResult(
                tool=tool,
                command=command,
                status="failed",
                attempts=attempt,
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                return_code=None,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                error=f"timeout:{timeout_seconds}s",
            )
        except FileNotFoundError:
            ended_at = datetime.now(timezone.utc)
            duration_ms = int((ended_at - started_at).total_seconds() * 1000)
            result = ToolExecutionResult(
                tool=tool,
                command=command,
                status="failed",
                attempts=attempt,
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
                return_code=None,
                stdout="",
                stderr="",
                error=f"tool_not_found:{tool}",
            )

        last_result = result
        if result.status == "success":
            return result

    return last_result  # type: ignore[return-value]
