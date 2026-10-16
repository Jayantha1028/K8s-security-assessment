import json


def _severity_bucket(score):
    """Map a 0-10 Kubescape score to a severity bucket name."""
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _as_float(value, default=0.0):
    try:
        return float(value or default)
    except (TypeError, ValueError):
        return default


def _as_int(value, default=0):
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _status_name(status):
    """Kubescape status is either a string or {"status": "failed", ...}."""
    if isinstance(status, dict):
        status = status.get("status")
    return str(status or "").lower()


def parse_kubescape(filename):
    """Read a Kubescape v2 report from disk (see parse_kubescape_data)."""
    with open(filename, encoding="utf-8") as file:
        data = json.load(file)
    return parse_kubescape_data(data, source=filename)


def parse_kubescape_data(data, source="report"):
    """
    Summarise an already-loaded machine-readable Kubescape v2 report.

    Taking the parsed JSON (rather than a filename) lets callers that have
    already loaded the file avoid reading and parsing it a second time.

    Two report shapes are understood, because the JSON layout differs
    between Kubescape releases:

    * flat shape: ``results`` entries carry their own ``status`` and
      ``baseScore`` and ``summaryDetails.statusCounters`` holds totals;
    * control-based shape: failures are listed under
      ``summaryDetails.controls`` (each with ``status`` and
      ``scoreFactor``).

    The flat shape is used whenever it yields data, so existing reports
    parse exactly as before. Otherwise the control-based shape is used.
    Always validate against a real report from the installed Kubescape.
    """
    if not isinstance(data, dict):
        raise ValueError(f"{source}: Kubescape report is not a JSON object")

    summary = data.get("summaryDetails") or {}
    counters = summary.get("statusCounters") or {}

    failed = _as_int(counters.get("failed"))
    passed = _as_int(counters.get("passed"))
    skipped = _as_int(counters.get("skipped"))
    compliance = _as_float(summary.get("complianceScore"))

    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    flat_results_seen = False

    for result in data.get("results") or []:
        if not isinstance(result, dict) or "status" not in result:
            continue
        flat_results_seen = True
        if _status_name(result.get("status")) != "failed":
            continue
        score = _as_float(
            result.get("baseScore")
            or result.get("score")
            or result.get("scoreFactor")
        )
        buckets[_severity_bucket(score)] += 1

    if not flat_results_seen:
        controls = summary.get("controls") or {}
        control_status = {"failed": 0, "passed": 0, "skipped": 0}

        if isinstance(controls, dict):
            for control in controls.values():
                if not isinstance(control, dict):
                    continue
                status = _status_name(
                    control.get("status") or control.get("statusInfo")
                )
                if status in ("failed", "passed"):
                    control_status[status] += 1
                elif status:
                    control_status["skipped"] += 1

                if status == "failed":
                    score = _as_float(
                        control.get("scoreFactor") or control.get("baseScore")
                    )
                    buckets[_severity_bucket(score)] += 1

        if not (failed or passed or skipped):
            failed = control_status["failed"]
            passed = control_status["passed"]
            skipped = control_status["skipped"]

    return {
        "kubescape_compliance": round(compliance, 2),
        "kubescape_failed": failed,
        "kubescape_passed": passed,
        "kubescape_skipped": skipped,
        "kubescape_critical": buckets["critical"],
        "kubescape_high": buckets["high"],
        "kubescape_medium": buckets["medium"],
        "kubescape_low": buckets["low"],
    }
