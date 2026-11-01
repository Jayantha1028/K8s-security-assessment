"""
Shared cleansing step for every CSV this project generates for the ML
models (kubernetes_security_dataset.csv and final_security_dataset.csv).

Both dataset builders assemble rows from several independent sources
(YAML parsing, Kubescape JSON, Trivy JSON, Falco logs, kubectl JSON).
Any one of those can be missing, malformed, or out of range for a given
row, and a raw pd.DataFrame.to_csv() call was previously the last step
in the pipeline, no matter what those rows looked like. That silently
hands the model NaNs, negative counts, out-of-range percentages, and
exact duplicate rows, all of which either break training or quietly
bias it (a duplicated row is double-counted evidence for the model).

clean_dataset() fixes that in one place, and returns a report so the
pipeline scripts can print what was changed instead of doing it blind.
"""

from dataclasses import dataclass, field
import numpy as np
import pandas as pd


@dataclass
class CleaningReport:
    rows_before: int = 0
    rows_after: int = 0
    duplicate_rows_dropped: int = 0
    filled_missing: dict = field(default_factory=dict)   # column -> count
    clipped_out_of_range: dict = field(default_factory=dict)  # column -> count
    dropped_missing_key: int = 0
    infinite_replaced: dict = field(default_factory=dict)     # column -> count
    whitespace_stripped: dict = field(default_factory=dict)   # column -> count
    string_missing_filled: dict = field(default_factory=dict) # column -> count
    zero_variance_features: list = field(default_factory=list)

    def print(self, label="Dataset"):
        print(f"\n=== {label}: cleansing report ===")
        print(f"Rows in:  {self.rows_before}")
        print(f"Rows out: {self.rows_after}")

        if self.dropped_missing_key:
            print(
                f"Dropped {self.dropped_missing_key} row(s) missing a "
                "required key column"
            )

        if self.duplicate_rows_dropped:
            print(
                f"Dropped {self.duplicate_rows_dropped} exact-duplicate "
                "row(s)"
            )
        else:
            print("No exact-duplicate rows found")

        if self.whitespace_stripped:
            print("Sanitized string columns (stripped leading/trailing whitespace):")
            for col, count in self.whitespace_stripped.items():
                print(f"  {col}: {count} row(s)")

        if self.infinite_replaced:
            print("Replaced infinite values (+/- inf -> NaN/0):")
            for col, count in self.infinite_replaced.items():
                print(f"  {col}: {count} row(s)")

        if self.filled_missing:
            print("Filled missing values:")
            for col, count in self.filled_missing.items():
                print(f"  {col}: {count} row(s) -> 0")
        else:
            print("No missing values in numeric columns")

        if self.string_missing_filled:
            print("Filled missing categorical/string values:")
            for col, count in self.string_missing_filled.items():
                print(f"  {col}: {count} row(s)")

        if self.clipped_out_of_range:
            print("Clipped out-of-range values:")
            for col, count in self.clipped_out_of_range.items():
                print(f"  {col}: {count} row(s)")

        if self.zero_variance_features:
            print(f"Note: Zero-variance features detected: {', '.join(self.zero_variance_features)}")


def clean_dataset(
    df,
    count_columns=None,
    bounded_columns=None,
    key_columns=None,
    dedup_subset=None,
    max_count_cap=100000,
    string_fill_default="Unknown",
):
    """
    Clean a raw assembled dataset before it is written to CSV.

    count_columns:       non-negative integer feature/label columns
                         (e.g. kubescape_failed, secret_count). Missing
                         values become 0, negatives are clipped to 0.
    bounded_columns:     dict of {column: (min, max)} for columns that must
                         fall in a known range (e.g. a 0-100 score).
    key_columns:         columns that must be present and non-null for the
                         row to be usable at all (e.g. the workload name);
                         rows missing these are dropped, not filled.
    dedup_subset:        columns compared to find exact-duplicate rows.
                         Defaults to every column (a full-row match), so two
                         rows only count as duplicates when every column,
                         including any key column, is identical. Pass a
                         narrower list (e.g. just an identity/snapshot
                         column) when duplicates should be judged by
                         identity alone.
    max_count_cap:       maximum allowable count value for count_columns to prevent
                         corrupted log parsers or integer overflows from distorting ML models.
    string_fill_default: default string to fill remaining string/object NaNs.
    """
    if df.empty:
        return df.copy(), CleaningReport()

    df = df.copy()
    count_columns = count_columns or []
    bounded_columns = bounded_columns or {}
    key_columns = key_columns or []

    report = CleaningReport(rows_before=len(df))

    # 1. String Sanitization: Strip leading/trailing whitespace across all text columns
    # and normalize standard categorical values.
    text_cols = list(df.select_dtypes(include=["object", "string"]).columns)
    for col in text_cols:
        mask_non_null = df[col].notna()
        stripped = df.loc[mask_non_null, col].astype(str).str.strip()
        num_changed = int((df.loc[mask_non_null, col].astype(str) != stripped).sum())
        if num_changed > 0:
            report.whitespace_stripped[col] = num_changed
            df.loc[mask_non_null, col] = stripped

        # Normalize known categorical columns
        if col == "risk_level":
            df[col] = df[col].astype(str).str.strip().str.capitalize()
            # Canonical mapping for risk levels
            valid_risks = {"Low": "Low", "Medium": "Medium", "High": "High"}
            df[col] = df[col].map(lambda x: valid_risks.get(x, x))
        elif col == "environment":
            df[col] = df[col].astype(str).str.strip().str.lower()

    # 2. Drop rows missing an identifying key outright (or empty string keys)
    if key_columns:
        before = len(df)
        valid_keys = [c for c in key_columns if c in df.columns]
        if valid_keys:
            # Drop NaN keys
            df = df.dropna(subset=valid_keys)
            # Drop empty / whitespace-only keys
            for k in valid_keys:
                if df[k].dtype.kind in ("O", "U", "S") or df[k].dtype.name in ("string", "str"):
                    df = df[df[k].astype(str).str.strip() != ""]
        report.dropped_missing_key = before - len(df)

    # 3. Sanitize infinite values (+/- np.inf) across all numeric columns to np.nan
    for col in df.select_dtypes(include=[np.number]).columns:
        inf_mask = np.isinf(df[col])
        inf_count = int(inf_mask.sum())
        if inf_count > 0:
            report.infinite_replaced[col] = inf_count
            df.loc[inf_mask, col] = np.nan

    # 4. Fill missing numeric feature/count columns with 0 and enforce non-negative integers.
    for col in count_columns:
        if col not in df.columns:
            continue

        # Convert to numeric, converting unparseable text or inf to NaN
        df[col] = pd.to_numeric(df[col], errors="coerce")
        inf_mask = np.isinf(df[col])
        if inf_mask.any():
            report.infinite_replaced[col] = report.infinite_replaced.get(col, 0) + int(inf_mask.sum())
            df.loc[inf_mask, col] = np.nan

        missing = int(df[col].isna().sum())
        if missing:
            report.filled_missing[col] = missing
            df[col] = df[col].fillna(0)

        # Clip lower bound (non-negative)
        negative = int((df[col] < 0).sum())
        if negative:
            report.clipped_out_of_range[col] = (
                report.clipped_out_of_range.get(col, 0) + negative
            )
        
        # Outlier cap protection: upper bound check
        if max_count_cap is not None:
            over_max = int((df[col] > max_count_cap).sum())
            if over_max:
                report.clipped_out_of_range[col] = (
                    report.clipped_out_of_range.get(col, 0) + over_max
                )
            df[col] = df[col].clip(lower=0, upper=max_count_cap)
        else:
            df[col] = df[col].clip(lower=0)

        df[col] = df[col].astype(int)

    # 5. Clip bounded columns (e.g. 0-100 scores)
    for col, (low, high) in bounded_columns.items():
        if col not in df.columns:
            continue

        df[col] = pd.to_numeric(df[col], errors="coerce")
        inf_mask = np.isinf(df[col])
        if inf_mask.any():
            report.infinite_replaced[col] = report.infinite_replaced.get(col, 0) + int(inf_mask.sum())
            df.loc[inf_mask, col] = np.nan
        df[col] = df[col].fillna(low)
        out_of_range = int(((df[col] < low) | (df[col] > high)).sum())
        if out_of_range:
            report.clipped_out_of_range[col] = out_of_range
        df[col] = df[col].clip(lower=low, upper=high)

    # 6. Fill remaining missing values in object/string columns to guarantee zero unhandled NaNs
    text_cols = list(df.select_dtypes(include=["object", "string"]).columns)
    for col in text_cols:
        missing_str = int(df[col].isna().sum())
        if missing_str > 0:
            report.string_missing_filled[col] = missing_str
            df[col] = df[col].fillna(string_fill_default)

    # 7. Drop duplicate rows
    before = len(df)
    df = df.drop_duplicates(subset=dedup_subset, keep="first")
    report.duplicate_rows_dropped = before - len(df)

    # 8. Zero-variance diagnostic check for numeric features
    for col in df.select_dtypes(include=[np.number]).columns:
        if len(df) > 1 and df[col].nunique() == 1:
            report.zero_variance_features.append(col)

    report.rows_after = len(df)
    return df.reset_index(drop=True), report
