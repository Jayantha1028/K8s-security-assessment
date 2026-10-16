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


@dataclass
class CleaningReport:
    rows_before: int = 0
    rows_after: int = 0
    duplicate_rows_dropped: int = 0
    filled_missing: dict = field(default_factory=dict)   # column -> count
    clipped_out_of_range: dict = field(default_factory=dict)  # column -> count
    dropped_missing_key: int = 0

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

        if self.filled_missing:
            print("Filled missing values:")
            for col, count in self.filled_missing.items():
                print(f"  {col}: {count} row(s) -> 0")
        else:
            print("No missing values in numeric columns")

        if self.clipped_out_of_range:
            print("Clipped out-of-range values:")
            for col, count in self.clipped_out_of_range.items():
                print(f"  {col}: {count} row(s)")


def clean_dataset(
    df,
    count_columns=None,
    bounded_columns=None,
    key_columns=None,
    dedup_subset=None,
):
    """
    Clean a raw assembled dataset before it is written to CSV.

    count_columns:   non-negative integer feature/label columns
                      (e.g. kubescape_failed, secret_count). Missing
                      values become 0, negatives are clipped to 0.
    bounded_columns: dict of {column: (min, max)} for columns that must
                      fall in a known range (e.g. a 0-100 score).
    key_columns:      columns that must be present and non-null for the
                      row to be usable at all (e.g. the workload name);
                      rows missing these are dropped, not filled.
    dedup_subset:     columns compared to find exact-duplicate rows.
                      Defaults to every column (a full-row match), so two
                      rows only count as duplicates when every column,
                      including any key column, is identical. Pass a
                      narrower list (e.g. just an identity/snapshot
                      column) when duplicates should be judged by
                      identity alone.
    """
    import pandas as pd

    count_columns = count_columns or []
    bounded_columns = bounded_columns or {}
    key_columns = key_columns or []

    report = CleaningReport(rows_before=len(df))

    # 1. Drop rows missing an identifying key outright (nothing to fill
    #    them with safely; keeping them would attribute other rows'
    #    features to an unknown or blank workload/snapshot).
    if key_columns:
        before = len(df)
        df = df.dropna(subset=[c for c in key_columns if c in df.columns])
        report.dropped_missing_key = before - len(df)

    # 2. Fill missing numeric feature/count columns with 0 and enforce
    #    non-negative integers. A missing value here means "the tool
    #    output was absent for this row", which is equivalent to a zero
    #    finding, not an unknown quantity — so 0 is the correct fill,
    #    not the column mean/median.
    for col in count_columns:
        if col not in df.columns:
            continue

        missing = int(df[col].isna().sum())
        if missing:
            report.filled_missing[col] = missing

        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

        negative = int((df[col] < 0).sum())
        if negative:
            report.clipped_out_of_range[col] = (
                report.clipped_out_of_range.get(col, 0) + negative
            )
        df[col] = df[col].clip(lower=0).astype(int)

    # 3. Clip bounded columns (e.g. a 0-100 compliance/security score)
    #    into their valid range instead of letting a bad upstream value
    #    (a negative score, a >100 percentage) train the model.
    for col, (low, high) in bounded_columns.items():
        if col not in df.columns:
            continue

        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(low)
        out_of_range = int(((df[col] < low) | (df[col] > high)).sum())
        if out_of_range:
            report.clipped_out_of_range[col] = out_of_range
        df[col] = df[col].clip(lower=low, upper=high)

    # 4. Drop exact-duplicate rows. This is not the same as duplicate
    #    *feature patterns* (a hardened/medium/weak generator profile is
    #    supposed to repeat across many differently-named workloads) -
    #    by default every column, including the key columns, must match
    #    for two rows to count as the same observation, so two distinct
    #    workloads that happen to share a feature/finding profile are
    #    correctly kept as separate rows. Pass dedup_subset explicitly
    #    when duplicates should instead be judged by identity alone
    #    (e.g. same snapshot name reused) regardless of other columns.
    before = len(df)
    df = df.drop_duplicates(subset=dedup_subset, keep="first")
    report.duplicate_rows_dropped = before - len(df)

    report.rows_after = len(df)
    return df.reset_index(drop=True), report
