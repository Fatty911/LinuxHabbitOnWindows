#!/usr/bin/env python3
"""LOCAL PROTOTYPE ONLY: bounded, exact-object non-MD Gitleaks adapter."""
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile

BASE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('reviewed_git', BASE / 'reviewed/markdown_privacy_gate.py')
git = importlib.util.module_from_spec(spec)
exec(compile(spec.origin and Path(spec.origin).read_bytes(), spec.origin, 'exec'), git.__dict__)
GITLEAKS = Path(os.environ.get('PUBLIC_SECRET_GITLEAKS', '/nonexistent'))
TOOL_SHA256 = '88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509'
MAX_FILES = 15000
MAX_FILE = 20 * 1024 * 1024
WINDOW_BYTES = 90000
OVERLAP_BYTES = 8192
MAX_WINDOWS = 20000
MAX_EXPORT = 160 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_REPORT = 8 * 1024 * 1024
ARCHIVES = {'.zip', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.tar', '.jar', '.war', '.zst', '.br'}
MAGIC = (b'PK\x03\x04', b'\x1f\x8b', b'BZh', b'\xfd7zXZ', b'7z\xbc\xaf\x27\x1c', b'Rar!', b'\x28\xb5\x2f\xfd')
Error = git.GateError

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_REPORT, MAX_REPORT))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    # Go reserves substantial virtual address space; use a deployment cgroup for RAM.

def text_supported(path, raw):
    if Path(path).suffix.lower() in ARCHIVES or raw.startswith(MAGIC) or raw[257:262] == b'ustar':
        raise Error('archive-not-covered')
    if b'\0' in raw:
        raise Error('binary-not-covered')
    try:
        raw.decode('utf-8')
    except UnicodeError:
        raise Error('encoding-not-covered') from None

def scan_export(export, mapping, temp, coverage=False, source="."):
    config = temp / 'trusted.toml'
    policy = (BASE / 'trusted-derived.toml').read_bytes()
    coverage_policy = (BASE / 'coverage.toml').read_bytes()
    if digest(policy) != 'd6849be1028e3d4bd631405a83c7931775a87b3e193c6fc0807800f8d77b2706' or digest(coverage_policy) != '7794cc46f005f0e9069b453f595901934d96d23f4ba74afe4c10815f181818d4':
        raise Error('policy-digest-mismatch')
    report_template = (BASE / 'metadata-report.tmpl').read_bytes()
    if digest(report_template) != '9b8ff567db40a2019b4a2722499cc8ac346dcdf1800ff3ea3e2bdd794591590a':
        raise Error('report-template-digest-mismatch')
    template_path = temp / 'metadata-report.tmpl'
    template_path.write_bytes(report_template)
    config.write_bytes(policy)
    ignore = temp / 'empty.ignore'
    ignore.write_bytes(b'')
    report = temp / 'report.json'
    cmd = [str(GITLEAKS), 'dir', source, '--config', str(config),
           '--gitleaks-ignore-path', str(ignore), '--ignore-gitleaks-allow',
           '--redact=100', '--no-banner', '--no-color', '--log-level', 'error',
           '--max-archive-depth', '0', '--max-decode-depth', '5', '--timeout', '0',
           '--report-format', 'template', '--report-template', str(template_path), '--report-path', str(report)]
    env = {'PATH': os.defpath, 'HOME': str(temp), 'LC_ALL': 'C', 'GOMAXPROCS': '2', 'GOMEMLIMIT': '256MiB'}
    try:
        completed = subprocess.run(cmd, cwd=export, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=60, preexec_fn=limits)
        if completed.returncode not in (0, 1):
            raise Error('scanner-failed')
        with report.open('rb') as stream:
            data = stream.read(MAX_REPORT + 1)
        if len(data) > MAX_REPORT:
            raise Error('report-limit')
        rows = json.loads(data)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise Error('scanner-incomplete') from None
    if not isinstance(rows, list) or len(rows) > 2 * MAX_WINDOWS + 10000 or bool(rows) != (completed.returncode == 1):
        raise Error('scanner-report-invalid')
    findings = []
    covered = Counter()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'File', 'RuleID', 'StartLine', 'EndLine', 'StartColumn', 'EndColumn', 'Tags'}:
            raise Error('scanner-report-invalid')
        name = row.get('File')
        # Accept only engine-generated paths corresponding exactly to verified relative paths.
        entry = mapping.get(name)
        rule = row.get('RuleID')
        line = row.get('StartLine')
        if entry is None or not isinstance(rule, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,99}', rule) or type(line) is not int or not 0 <= line <= MAX_FILE + 1:
            raise Error('scanner-report-invalid')
        if any(type(row[k]) is not int for k in ('StartLine', 'EndLine', 'StartColumn', 'EndColumn')):
            raise Error('scanner-report-invalid')
        tags = row['Tags']
        if tags is None:
            tags = []
        if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
            raise Error('scanner-report-invalid')
        if rule in {'adapter-coverage', 'adapter-coverage-tail'}:
            if tags:
                if not all(re.fullmatch(r'(?:decoded:[a-z0-9-]+|decode-depth:[1-5])', t) for t in tags) or not any(t.startswith('decoded:') for t in tags) or not any(t.startswith('decode-depth:') for t in tags):
                    raise Error('scanner-report-invalid')
                # Only raw-pass controls attest source traversal; decoding can add
                # tagged views but cannot substitute for the exact raw rows.
                continue
            signature = tuple(row.get(k) for k in ('StartLine', 'EndLine', 'StartColumn', 'EndColumn'))
            signature_key = 'coverage_signature' if rule == 'adapter-coverage' else 'coverage_tail_signature'
            if signature_key in entry and signature != entry[signature_key]:
                raise Error('scanner-coverage-range-mismatch')
            covered[(rule, entry.get('coverage_id', entry['file_id']))] += 1
            continue
        # Never publish Secret, Match, Description, Fingerprint, raw paths or stderr.
        findings.append({'file_id': entry['file_id'], 'blob': entry['blob'], 'rule': rule, 'line': line + entry.get('line_offset', 0) if line else 0})
    required = Counter({(rule, item.get('coverage_id', item['file_id'])): 1 for item in mapping.values() if item.get('bytes', 1) for rule in (['adapter-coverage'] + (['adapter-coverage-tail'] if item.get('has_tail', True) else []))})
    if covered != required:
        raise Error('scanner-coverage-incomplete')
    return findings

def windows(raw):
    if not raw:
        yield 0, b''
        return
    start = 0
    while start < len(raw):
        end = min(len(raw), start + WINDOW_BYTES)
        while end < len(raw) and raw[end] & 0xC0 == 0x80:
            end -= 1
        yield start, raw[start:end]
        if end == len(raw):
            break
        start = end - OVERLAP_BYTES
        while start and raw[start] & 0xC0 == 0x80:
            start -= 1

# All five exact predicates in pinned upstream config; no guessed generic RE2 port.
PATH_PREDICATES = {
    'freemius-secret-key': r'(?i)\.php$',
    'hashicorp-tf-password': r'(?i)\.(?:tf|hcl)$',
    'kubernetes-secret-yaml': r'(?i)\.ya?ml$',
    'nuget-config-password': r'(?i)nuget\.config$',
    'pkcs12-file': r'(?i)(?:^|\/)[^\/]+\.p(?:12|fx)$',
}

def assert_path_equivalence(original, window_path):
    for pattern in PATH_PREDICATES.values():
        if bool(re.search(pattern, original)) != bool(re.search(pattern, window_path)):
            raise Error('path-semantics-mismatch')

def verify_export(export, mapping):
    for name, item in mapping.items():
        target = export / name
        if target.is_symlink() or not target.is_file():
            raise Error('export-integrity-mismatch')
        with target.open('rb') as stream:
            raw = stream.read(WINDOW_BYTES + 1)
        if len(raw) != item['bytes'] or digest(raw) != item['chunk_sha256']:
            raise Error('export-integrity-mismatch')

def coverage_signature(raw, start=0, end=None):
    # Exact byte-index location behavior from pinned detect/location.go. Engine
    # trims LF at both ends of a match before calculating its final match index.
    if end is None:
        end = len(raw.strip(b'\n'))
    indices = [i for i, b in enumerate(raw) if b == 10] or [len(raw)]
    prev = 0
    start_line = end_line = start_col = end_col = 0
    line_set = False
    for number, newline in enumerate(indices):
        if prev <= start < newline:
            line_set = True
            start_line = end_line = number
            start_col = start + 1 - prev
        if prev < end <= newline:
            end_line = number
            end_col = end - prev
        prev = newline
    if not line_set:
        start_col = start + 1 - prev
        end_col = end - prev
        start_line = end_line = number + 1
    return start_line + 1, end_line + 1, start_col, end_col

def coverage_tail_signature(raw):
    # Go regexp matches the final non-LF UTF8 rune, not its final byte. The
    # pinned location implementation still reports byte-indexed columns.
    end = len(raw.rstrip(b'\n'))
    start = end - 1
    while start > 0 and raw[start] & 0xC0 == 0x80:
        start -= 1
    return coverage_signature(raw, start, end)

def check(repo, revision):
    if digest(GITLEAKS.read_bytes()) != TOOL_SHA256:
        raise Error('scanner-digest-mismatch')
    scanner = git.load_scanner()
    fd = scanner.open_directory(repo)
    os.close(fd)
    kind, tree, entries = git.inventory(repo, revision)
    selected = [e for e in entries if Path(e['path']).suffix.lower() not in {'.md', '.mdx'}]
    if len(selected) > MAX_FILES:
        raise Error('file-count-limit')
    git.MAX_DOCUMENTS, git.MAX_BLOB_BYTES, git.MAX_TOTAL_BYTES = MAX_FILES, MAX_FILE, MAX_TOTAL
    contents = git.blobs(repo, selected) if selected else {}
    manifest = []
    with tempfile.TemporaryDirectory(prefix='secret-gate-') as directory:
        temp = Path(directory)
        export = temp / 'snapshot'
        export.mkdir()
        mapping = {}
        total_export = 0
        windows_count = 0
        for entry in selected:
            raw = contents[entry['path']]
            text_supported(entry['path'], raw)
            item = {'file_id': digest(entry['path'].encode()), 'blob': entry['blob'], 'mode': entry['mode'], 'bytes': len(raw)}
            manifest.append(item)
            last_offset = line_offset = 0
            for index, (offset, chunk) in enumerate(windows(raw)):
                line_offset += raw[last_offset:offset].count(b'\n')
                last_offset = offset
                windows_count += 1
                total_export += len(chunk)
                if windows_count > MAX_WINDOWS or total_export > MAX_EXPORT:
                    raise Error('window-budget-limit')
                # Prefix is neutral for every pinned path detector; asserted below.
                name = 'window-' + str(index) + '/' + entry['path']
                assert_path_equivalence(entry['path'], name)
                target = export / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(chunk)
                mapping[name] = {**item, 'bytes': len(chunk), 'coverage_id': digest(name.encode()),
                                 'chunk_sha256': digest(chunk), 'line_offset': line_offset,
                                 'coverage_signature': coverage_signature(chunk),
                                 'has_tail': bool(chunk.rstrip(b'\n')),
                                 'coverage_tail_signature': coverage_tail_signature(chunk)}
        verify_export(export, mapping)
        findings = scan_export(export, mapping, temp) if mapping else []
        verify_export(export, mapping)
        for entry, item in zip(selected, manifest):
            if not item['bytes'] and Path(entry['path']).suffix.lower() in {'.p12', '.pfx'}:
                findings.append({'file_id': item['file_id'], 'blob': item['blob'], 'rule': 'pkcs12-file', 'line': 0})
        findings = list({(r['file_id'], r['blob'], r['rule'], r['line']): r for r in findings}.values())
    return {'version': 5, 'prototype': True, 'scope': 'exact-object-non-md-mdx-utf8-text',
            'revision': revision.lower(), 'revision_type': kind, 'tree': tree,
            'scanner_sha256': TOOL_SHA256, 'manifest': manifest,
            'status': 'findings' if findings else 'clean', 'detector_status': 'findings' if findings else 'clean',
            'window_count': windows_count, 'export_bytes': total_export, 'window_bytes': WINDOW_BYTES,
            'overlap_bytes': OVERLAP_BYTES, 'policy_sha256': digest((BASE / 'trusted-derived.toml').read_bytes()), 'findings': findings}

def main():
    parser = git.RedactedParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    args = parser.parse_args()
    try:
        result = check(args.repo, args.revision)
    except Error as exc:
        result = {'status': 'incomplete', 'errors': [{'code': str(exc)}]}
    except Exception:
        result = {'status': 'incomplete', 'errors': [{'code': 'adapter-failed'}]}
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return {'clean': 0, 'findings': 1, 'incomplete': 2}[result['status']]

if __name__ == '__main__':
    sys.exit(main())
