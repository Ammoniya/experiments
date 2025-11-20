from pathlib import Path
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

try:
    import pandas as pd
except ImportError:  # pragma: no cover
    pd = None

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None


def _extract_timestamp(file_path: Path) -> str:
    """Return the YYYYMMDD portion of the trace directory name."""
    ts = file_path.parent.name  # e.g., 20251119-123456 or 20251119
    if not ts:
        return "unknown"

    # Aggregate by date only, stripping the optional "-HHMMSS" suffix.
    day = ts.split("-", 1)[0]
    return day if day.isdigit() and len(day) == 8 else ts


def _format_table(headers, rows, aligns=None):
    """Render an ASCII table with optional column alignment specifiers."""
    str_headers = [str(h) for h in headers]
    str_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(h) for h in str_headers]
    for row in str_rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    if aligns is None:
        aligns = ["left"] * len(headers)

    def _hline(char="-"):
        return "+" + "+".join(char * (w + 2) for w in widths) + "+"

    def _format_row(row_vals):
        cells = []
        for idx, cell in enumerate(row_vals):
            if aligns[idx] == "right":
                cells.append(cell.rjust(widths[idx]))
            else:
                cells.append(cell.ljust(widths[idx]))
        return "| " + " | ".join(cells) + " |"

    lines = [_hline(), _format_row(str_headers), _hline("=")]
    for row in str_rows:
        lines.append(_format_row(row))
        lines.append(_hline())
    return "\n".join(lines)


def _print_table(rows, headers=None):
    headers = headers or ("Date", "Traces", "Scripts")
    if pd is not None:
        df = pd.DataFrame(rows, columns=headers)
        # Ensure numeric columns stay numeric for nicer markdown output
        for col_name in headers[1:]:
            df[col_name] = pd.to_numeric(df[col_name], errors="ignore")

        markdown_table = None
        try:
            markdown_table = df.to_markdown(index=False, tablefmt="github")
        except (ImportError, AttributeError):
            markdown_table = None

        if markdown_table:
            print(markdown_table)
            return

        with pd.option_context("display.max_rows", None, "display.max_columns", None):
            print(df.to_string(index=False))
        return

    aligns = ["left"] + ["right"] * (len(headers) - 1)
    print(_format_table(headers, rows, aligns=aligns))


def _count_loaded_scripts(loaded_js_dir: Path) -> int:
    """Return how many files exist under loaded_js (used as a script count proxy)."""
    if not loaded_js_dir.is_dir():
        return 0

    try:
        return sum(1 for path in loaded_js_dir.rglob('*') if path.is_file())
    except (OSError, PermissionError):
        return 0


def _per_file(path_str: str) -> tuple[str, int]:
    """Helper for multiprocessing that stays picklable."""
    trace_path = Path(path_str)
    ts_key = _extract_timestamp(trace_path)
    script_count = _count_loaded_scripts(trace_path.parent / 'loaded_js')
    return ts_key, script_count


def analyze_trace_files(root_dir='experiment_data'):
    trace_files = list(Path(root_dir).rglob('trace_v2.json'))

    if not trace_files:
        print("No trace_v2.json files found.")
        return

    # Count traces per timestamp directory
    counts = defaultdict(int)
    script_counts = defaultdict(int)

    trace_file_strs = [str(p) for p in trace_files]

    def _with_progress(iterable):
        if tqdm:
            return tqdm(iterable, total=len(trace_file_strs), desc="Counting traces", unit="file")
        return iterable

    try:
        with ProcessPoolExecutor() as executor:
            results_iter = _with_progress(executor.map(_per_file, trace_file_strs, chunksize=16))
            for ts_key, script_count in results_iter:
                counts[ts_key] += 1
                script_counts[ts_key] += script_count
    except (OSError, PermissionError) as exc:
        print(f"ProcessPoolExecutor unavailable ({exc}); falling back to single-process execution.")
        for ts_key, script_count in _with_progress(map(_per_file, trace_file_strs)):
            counts[ts_key] += 1
            script_counts[ts_key] += script_count

    timestamps_sorted = sorted(counts.keys())

    print(
        "Found "
        f"{len(trace_files)} trace_v2.json file(s) across {len(timestamps_sorted)} timestamp(s); "
        f"loaded {sum(script_counts.values())} script file(s)\n"
    )
    rows = []
    total_traces = 0
    total_scripts = 0
    for ts_key in timestamps_sorted:
        count = counts[ts_key]
        scripts = script_counts.get(ts_key, 0)
        rows.append((ts_key, count, scripts))
        total_traces += count
        total_scripts += scripts

    rows.append(("TOTAL", total_traces, total_scripts))

    _print_table(rows)


if __name__ == "__main__":
    analyze_trace_files()
