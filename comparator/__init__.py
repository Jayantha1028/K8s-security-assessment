"""
comparator
==========
Subfolder comparison package for benchmarking Native Security Scanner
against industry-standard scanners (Kubescape and Trivy).
"""

from comparator.cve_intelligence import (
    CVEEntry,
    lookup_image_cves,
    summarize_cve_counts,
    KNOWN_IMAGE_CVE_DB,
    get_total_indexed_cve_count,
    get_indexed_cve_ids,
)
from comparator.scanner_benchmark import (
    ScannerComparator,
    ScannerMetrics,
    BenchmarkComparisonResult,
)

__all__ = [
    "CVEEntry",
    "lookup_image_cves",
    "summarize_cve_counts",
    "KNOWN_IMAGE_CVE_DB",
    "ScannerComparator",
    "ScannerMetrics",
    "BenchmarkComparisonResult",
]
