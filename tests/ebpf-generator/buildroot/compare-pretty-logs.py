#!/usr/bin/env python3
"""Compare host and Buildroot guest Pretty Verifier logs."""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape


ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])?")
ILLEGAL_XML_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f]")
PRETTY_ERROR_RE = re.compile(r"^\s*(\d+)\s+error:\s*(.*)$")


@dataclass
class ParsedLog:
    filename: str
    status: str
    verifier_error: str
    pretty_error_number: str
    pretty_error: str
    pretty_log: str
    pretty_tail: str
    output_path: Path | None
    generated_log_path: Path | None


def strip_ansi(value: str) -> str:
    return ANSI_RE.sub("", value or "").replace("\r\n", "\n").replace("\r", "\n")


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")


def resolve_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def resolve_instance(repo_root: Path, value: str | None) -> tuple[str, Path]:
    instances_dir = repo_root / "buildroot" / "instances"
    if value:
        exact = instances_dir / value
        if (exact / "shared" / "bpf").is_dir():
            return exact.name, exact

        candidates = [instances_dir / f"linux-{value}"]
        if re.match(r"^\d+\.\d+$", value):
            candidates.extend(sorted(instances_dir.glob(f"linux-{value}.*")))
        matches = sorted({candidate for candidate in candidates if (candidate / "shared" / "bpf").is_dir()})
        if len(matches) == 1:
            return matches[0].name, matches[0]
        if len(matches) > 1:
            names = "\n".join(f"  {path.name}" for path in matches)
            raise SystemExit(f"More than one Buildroot instance matches {value!r}. Pass one explicitly:\n{names}")
        raise SystemExit(f"Could not find Buildroot instance for {value!r} under {instances_dir}")

    matches = sorted(path for path in instances_dir.glob("linux-*") if (path / "shared" / "bpf").is_dir())
    if len(matches) == 1:
        return matches[0].name, matches[0]
    if not matches:
        raise SystemExit(f"No Buildroot instances found under {instances_dir}")
    names = "\n".join(f"  {path.name}" for path in matches)
    raise SystemExit(f"More than one Buildroot instance exists. Pass one explicitly:\n{names}")


def output_to_source_name(output_name: str) -> str:
    if output_name.endswith("_output.txt"):
        return output_name[: -len("_output.txt")] + ".c"
    return Path(output_name).with_suffix(".c").name


def output_to_object_name(output_name: str) -> str:
    if output_name.endswith("_output.txt"):
        return output_name[: -len("_output.txt")] + ".o"
    return Path(output_name).with_suffix(".o").name


def load_excluded_tests(*paths: Path) -> set[str]:
    excluded: set[str] = set()
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            name = line.split("#", 1)[0].strip()
            if name:
                excluded.add(Path(name).name)
    return excluded


def find_pretty_start(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if "## Prettier Verifier ##" in line:
            start = index
            while start > 0 and lines[start - 1].strip().startswith("#"):
                start -= 1
            return start
    return None


def extract_pretty_log(text: str) -> str:
    lines = strip_ansi(text).splitlines()
    start = find_pretty_start(lines)
    if start is None:
        return ""

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].strip() == "-- END PROG LOAD LOG --":
            end = index
            break
    return "\n".join(lines[start:end]).strip()


def normalize_paths_for_display(text: str, workdir: Path) -> str:
    clean = text
    for value in {str(workdir), str(workdir.resolve())}:
        clean = clean.replace(value, ".")
    return clean


def extract_pretty_tail(text: str, workdir: Path) -> str:
    lines = strip_ansi(text).splitlines()
    marker = None
    for index, line in enumerate(lines):
        if "## Prettier Verifier ##" in line:
            marker = index
            break
    if marker is None:
        return ""

    start = marker + 1
    while start < len(lines):
        stripped = lines[start].strip()
        if stripped and not stripped.startswith("#"):
            break
        start += 1

    body: list[str] = []
    for line in lines[start:]:
        stripped = line.strip()
        if stripped == "-- END PROG LOAD LOG --":
            break
        if re.match(r"^ERROR:\s+Invalid object file\s+\S+\.o$", stripped):
            continue
        body.append(line)

    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()

    return normalize_paths_for_display("\n".join(body), workdir)


def extract_pretty_error(pretty_log: str) -> tuple[str, str]:
    for line in pretty_log.splitlines():
        match = PRETTY_ERROR_RE.match(line.strip())
        if match:
            return match.group(1), match.group(2).strip()
    return "N/A", "N/A"


def extract_verifier_error(text: str) -> str:
    lines = strip_ansi(text).splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("processed"):
            if index > 0:
                return lines[index - 1].strip() or "N/A"
            return "N/A"
    return "N/A"


def run_pretty_verifier(
    pretty_verifier_dir: Path,
    output_path: Path,
    workdir: Path,
    timeout: int,
) -> tuple[str, str]:
    source = workdir / output_to_source_name(output_path.name)
    obj = workdir / output_to_object_name(output_path.name)
    if not source.exists():
        return output_path.read_text(encoding="utf-8", errors="replace"), f"missing source {source.name}"
    if not obj.exists():
        return output_path.read_text(encoding="utf-8", errors="replace"), f"missing bytecode {obj.name}"

    cmd = [
        sys.executable,
        str(pretty_verifier_dir / "pretty_verifier.py"),
        "-l",
        str(output_path),
        "-c",
        str(source),
        "-o",
        str(obj),
        "-n",
    ]
    try:
        result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return output_path.read_text(encoding="utf-8", errors="replace"), "pretty timeout"

    text = result.stdout + result.stderr
    if not text.strip():
        text = output_path.read_text(encoding="utf-8", errors="replace")
    status = "ok" if result.returncode == 0 else f"pretty rc={result.returncode}"
    return text, status


def normalize_log(
    label: str,
    output_path: Path | None,
    workdir: Path,
    pretty_verifier_dir: Path,
    log_dir: Path,
    force_pretty: bool,
    timeout: int,
) -> ParsedLog:
    filename = output_path.name if output_path else label
    if output_path is None or not output_path.exists():
        return ParsedLog(
            filename=filename,
            status="missing output",
            verifier_error="N/A",
            pretty_error_number="N/A",
            pretty_error="N/A",
            pretty_log="",
            pretty_tail="",
            output_path=output_path,
            generated_log_path=None,
        )

    raw = output_path.read_text(encoding="utf-8", errors="replace")
    status = "ok"
    if force_pretty or not extract_pretty_log(raw):
        raw, status = run_pretty_verifier(pretty_verifier_dir, output_path, workdir, timeout)

    clean = strip_ansi(raw)
    pretty_log = extract_pretty_log(clean)
    pretty_tail = extract_pretty_tail(clean, workdir)
    pretty_error_number, pretty_error = extract_pretty_error(pretty_log)
    if not pretty_log and status == "ok":
        status = "missing pretty log"

    log_dir.mkdir(parents=True, exist_ok=True)
    generated_log = log_dir / output_path.name
    generated_log.write_text(clean, encoding="utf-8")

    return ParsedLog(
        filename=output_path.name,
        status=status,
        verifier_error=extract_verifier_error(clean),
        pretty_error_number=pretty_error_number,
        pretty_error=pretty_error,
        pretty_log=pretty_log,
        pretty_tail=pretty_tail,
        output_path=output_path,
        generated_log_path=generated_log,
    )


def bool_text(value: bool) -> str:
    return "YES" if value else "NO"


def comparable(value: str) -> str:
    return strip_ansi(value).strip()


def make_report_rows(
    names: list[str],
    host_by_name: dict[str, ParsedLog],
    kernel_by_name: dict[str, ParsedLog],
    differences_only: bool,
) -> tuple[list[list[object]], list[list[int | None]], dict[str, int]]:
    header = [
        "file",
        "host status",
        "kernel status",
        "host verifier error",
        "kernel verifier error",
        "verifier differs",
        "host pretty error number",
        "kernel pretty error number",
        "pretty number differs",
        "host pretty error",
        "kernel pretty error",
        "pretty error differs",
        "host pretty verifier output",
        "kernel pretty verifier output",
        "pretty verifier output differs",
        "any differs",
        "host normalized log",
        "kernel normalized log",
    ]
    rows: list[list[object]] = [header]
    styles: list[list[int | None]] = [[1 for _ in header]]
    summary = {
        "total": 0,
        "any_different": 0,
        "verifier_different": 0,
        "pretty_number_different": 0,
        "pretty_error_different": 0,
        "pretty_output_different": 0,
    }

    for name in names:
        host = host_by_name[name]
        kernel = kernel_by_name[name]
        verifier_diff = comparable(host.verifier_error) != comparable(kernel.verifier_error)
        pretty_number_diff = comparable(host.pretty_error_number) != comparable(kernel.pretty_error_number)
        pretty_error_diff = comparable(host.pretty_error) != comparable(kernel.pretty_error)
        pretty_output_diff = comparable(host.pretty_tail) != comparable(kernel.pretty_tail)
        any_diff = verifier_diff or pretty_number_diff or pretty_error_diff or pretty_output_diff

        summary["total"] += 1
        summary["any_different"] += int(any_diff)
        summary["verifier_different"] += int(verifier_diff)
        summary["pretty_number_different"] += int(pretty_number_diff)
        summary["pretty_error_different"] += int(pretty_error_diff)
        summary["pretty_output_different"] += int(pretty_output_diff)

        if differences_only and not any_diff:
            continue

        row = [
            name,
            host.status,
            kernel.status,
            host.verifier_error,
            kernel.verifier_error,
            bool_text(verifier_diff),
            host.pretty_error_number,
            kernel.pretty_error_number,
            bool_text(pretty_number_diff),
            host.pretty_error,
            kernel.pretty_error,
            bool_text(pretty_error_diff),
            host.pretty_tail,
            kernel.pretty_tail,
            bool_text(pretty_output_diff),
            bool_text(any_diff),
            str(host.generated_log_path or ""),
            str(kernel.generated_log_path or ""),
        ]
        row_style: list[int | None] = [None for _ in row]
        if host.status != "ok":
            row_style[1] = 4
        if kernel.status != "ok":
            row_style[2] = 4
        for left, right, flag in (
            (3, 4, verifier_diff),
            (6, 7, pretty_number_diff),
            (9, 10, pretty_error_diff),
            (12, 13, pretty_output_diff),
        ):
            if flag:
                row_style[left] = 2
                row_style[right] = 2
        for index, flag in (
            (5, verifier_diff),
            (8, pretty_number_diff),
            (11, pretty_error_diff),
            (14, pretty_output_diff),
            (15, any_diff),
        ):
            row_style[index] = 2 if flag else 3
        rows.append(row)
        styles.append(row_style)

    return rows, styles, summary


def xml_clean(value: object, max_chars: int) -> str:
    text = "" if value is None else str(value)
    text = ILLEGAL_XML_RE.sub("", text)
    if len(text) > max_chars:
        suffix = "\n[truncated for Excel cell]"
        text = text[: max(0, max_chars - len(suffix))] + suffix
    return text


def col_name(index: int) -> str:
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def cell_xml(row_idx: int, col_idx: int, value: object, max_chars: int, style: int | None) -> str:
    ref = f"{col_name(col_idx)}{row_idx}"
    attrs = f' r="{ref}" t="inlineStr"'
    if style is not None:
        attrs += f' s="{style}"'
    text = escape(xml_clean(value, max_chars))
    return f'<c{attrs}><is><t xml:space="preserve">{text}</t></is></c>'


def sheet_xml(rows: list[list[object]], styles: list[list[int | None]], max_chars: int) -> str:
    sheet_rows = []
    for row_idx, row in enumerate(rows, start=1):
        cells = []
        row_styles = styles[row_idx - 1] if row_idx - 1 < len(styles) else []
        for col_idx, value in enumerate(row, start=1):
            style = row_styles[col_idx - 1] if col_idx - 1 < len(row_styles) else None
            cells.append(cell_xml(row_idx, col_idx, value, max_chars, style))
        sheet_rows.append(f'<row r="{row_idx}">{"".join(cells)}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
        'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
        '<sheetFormatPr defaultRowHeight="15"/>'
        '<cols><col min="1" max="1" width="16" customWidth="1"/>'
        '<col min="2" max="3" width="18" customWidth="1"/>'
        '<col min="4" max="5" width="44" customWidth="1"/>'
        '<col min="6" max="11" width="18" customWidth="1"/>'
        '<col min="12" max="13" width="70" customWidth="1"/>'
        '<col min="14" max="16" width="18" customWidth="1"/>'
        '<col min="17" max="18" width="50" customWidth="1"/></cols>'
        '<sheetData>'
        + "".join(sheet_rows)
        + '</sheetData></worksheet>'
    )


def write_xlsx(path: Path, rows: list[list[object]], styles: list[list[int | None]], max_chars: int = 32000) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/styles.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            "</Types>",
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/>'
            "</Relationships>",
        )
        zf.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Pretty Compare" sheetId="1" r:id="rId1"/></sheets>'
            "</workbook>",
        )
        zf.writestr(
            "xl/_rels/workbook.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            'Target="worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
            'Target="styles.xml"/>'
            "</Relationships>",
        )
        zf.writestr(
            "xl/styles.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
            '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
            '<fills count="5"><fill><patternFill patternType="none"/></fill>'
            '<fill><patternFill patternType="gray125"/></fill>'
            '<fill><patternFill patternType="solid"><fgColor rgb="FFFFD966"/></patternFill></fill>'
            '<fill><patternFill patternType="solid"><fgColor rgb="FFC6EFCE"/></patternFill></fill>'
            '<fill><patternFill patternType="solid"><fgColor rgb="FFFFC7CE"/></patternFill></fill></fills>'
            '<borders count="1"><border/></borders>'
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="5"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
            '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFill="1"/>'
            '<xf numFmtId="0" fontId="0" fillId="2" borderId="0" xfId="0" applyFill="1"/>'
            '<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1"/>'
            '<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/></cellXfs>'
            '</styleSheet>',
        )
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml(rows, styles, max_chars))


def write_csv(path: Path, rows: list[list[object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerows(rows)


def rows_as_dicts(rows: list[list[object]]) -> list[dict[str, object]]:
    if not rows:
        return []
    header = [str(value) for value in rows[0]]
    return [dict(zip(header, row, strict=False)) for row in rows[1:]]


def discover_output_names(
    host_dir: Path,
    kernel_dir: Path,
    limit: int | None,
    excluded_tests: set[str],
) -> list[str]:
    names = {path.name for path in host_dir.glob("prog_*_output.txt")}
    names.update(path.name for path in kernel_dir.glob("prog_*_output.txt"))
    ordered = sorted(name for name in names if output_to_source_name(name) not in excluded_tests)
    if limit is not None:
        ordered = ordered[:limit]
    return ordered


def main() -> int:
    repo_root = resolve_repo_root()
    parser = argparse.ArgumentParser(description="Compare host and Buildroot Pretty Verifier outputs.")
    parser.add_argument("kernel", nargs="?", help="Kernel instance, e.g. 6.18, 6.18.36, or linux-6.18.36")
    parser.add_argument("--host-dir", type=Path, default=repo_root / "fuzzed-tests")
    parser.add_argument("--instance-dir", type=Path, help="Explicit Buildroot instance directory")
    parser.add_argument("--pretty-verifier-dir", type=Path, default=repo_root / "pretty-verifier")
    parser.add_argument("--output-dir", type=Path, default=repo_root / "buildroot" / "reports")
    parser.add_argument("--limit", type=int, help="Only process the first N outputs")
    parser.add_argument("--differences-only", action="store_true", help="Only include rows with at least one metric difference")
    parser.add_argument("--force-pretty", action="store_true", help="Regenerate Pretty Verifier logs even if already present")
    parser.add_argument("--pretty-timeout", type=int, default=30)
    args = parser.parse_args()

    if args.instance_dir:
        instance_dir = args.instance_dir.resolve()
        instance_name = instance_dir.name
    else:
        instance_name, instance_dir = resolve_instance(repo_root, args.kernel)

    host_dir = args.host_dir.resolve()
    kernel_dir = instance_dir / "shared" / "bpf"
    pretty_dir = args.pretty_verifier_dir.resolve()
    if not host_dir.is_dir():
        raise SystemExit(f"host dir not found: {host_dir}")
    if not kernel_dir.is_dir():
        raise SystemExit(f"kernel shared bpf dir not found: {kernel_dir}")
    if not (pretty_dir / "pretty_verifier.py").is_file():
        raise SystemExit(f"pretty_verifier.py not found under {pretty_dir}")

    report_dir = (args.output_dir / instance_name).resolve()
    host_log_dir = report_dir / "pretty-logs" / "host"
    kernel_log_dir = report_dir / "pretty-logs" / instance_name
    excluded_tests = load_excluded_tests(host_dir / "excluded_tests.txt", kernel_dir / "excluded_tests.txt")
    names = discover_output_names(host_dir, kernel_dir, args.limit, excluded_tests)
    if not names:
        raise SystemExit(f"no prog_*_output.txt files found in {host_dir} or {kernel_dir}")

    print(f"[pretty-compare] host: {host_dir}")
    print(f"[pretty-compare] kernel: {kernel_dir}")
    print(f"[pretty-compare] outputs: {len(names)}")
    if excluded_tests:
        print(f"[pretty-compare] excluded: {len(excluded_tests)}")

    host_by_name: dict[str, ParsedLog] = {}
    kernel_by_name: dict[str, ParsedLog] = {}
    for index, name in enumerate(names, start=1):
        print(f"[pretty-compare] {index}/{len(names)} {name}")
        host_output = host_dir / name
        kernel_output = kernel_dir / name
        host_by_name[name] = normalize_log(
            name,
            host_output if host_output.exists() else None,
            host_dir,
            pretty_dir,
            host_log_dir,
            args.force_pretty,
            args.pretty_timeout,
        )
        kernel_by_name[name] = normalize_log(
            name,
            kernel_output if kernel_output.exists() else None,
            kernel_dir,
            pretty_dir,
            kernel_log_dir,
            args.force_pretty,
            args.pretty_timeout,
        )

    rows, styles, summary = make_report_rows(names, host_by_name, kernel_by_name, args.differences_only)
    xlsx_path = report_dir / f"{instance_name}_pretty_compare_full.xlsx"
    csv_path = report_dir / f"{instance_name}_pretty_compare_full.csv"
    json_path = report_dir / f"{instance_name}_pretty_compare_full.json"
    write_xlsx(xlsx_path, rows, styles)
    write_csv(csv_path, rows)
    json_report = {
        "instance": instance_name,
        "host_dir": str(host_dir),
        "kernel_dir": str(kernel_dir),
        "differences_only": args.differences_only,
        "limit": args.limit,
        "summary": summary,
        "outputs": {
            "xlsx": str(xlsx_path),
            "csv": str(csv_path),
            "json": str(json_path),
            "host_pretty_logs": str(host_log_dir),
            "kernel_pretty_logs": str(kernel_log_dir),
        },
        "rows": rows_as_dicts(rows),
    }
    json_path.write_text(json.dumps(json_report, indent=2, sort_keys=True), encoding="utf-8")

    print(f"[pretty-compare] wrote {xlsx_path}")
    print(f"[pretty-compare] wrote {csv_path}")
    print(f"[pretty-compare] wrote {json_path}")
    print(
        "[pretty-compare] summary: "
        f"{summary['any_different']}/{summary['total']} rows differ; "
        f"verifier={summary['verifier_different']}, "
        f"pretty-number={summary['pretty_number_different']}, "
        f"pretty-error={summary['pretty_error_different']}, "
        f"pretty-output={summary['pretty_output_different']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
