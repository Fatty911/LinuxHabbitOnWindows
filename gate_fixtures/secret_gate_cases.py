import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import tomllib
from unittest.mock import patch
import importlib.util
import sys
GATE_PATH = Path(__file__).resolve().parents[1] / 'scripts/secret_gate/gate.py'
spec = importlib.util.spec_from_file_location('gate', GATE_PATH)
gate = importlib.util.module_from_spec(spec)
exec(compile(GATE_PATH.read_bytes(), str(GATE_PATH), 'exec'), gate.__dict__)

# Deliberately fabricated, never validated against any service.
SYNTHETIC = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'

class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='synthetic-gate-test-')
        self.repo = Path(self.tmp.name) / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic Test')
        self.git('config', 'user.email', 'synthetic@example.invalid')
    def tearDown(self):
        self.tmp.cleanup()
    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL).decode().strip()
    def commit(self, files):
        for name, content in files.items():
            p = self.repo / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content if isinstance(content, bytes) else content.encode())
        self.git('add', '--all', '--force')
        self.git('commit', '-qm', 'synthetic fixture')
        return self.git('rev-parse', 'HEAD')
    def test_bedrock_representation_keeps_detection(self):
        value = 'bedrock-api-key-' + base64.b64encode(b'bedrock.amazonaws.com').decode()
        rev = self.commit({'fixture.txt': value})
        self.assertIn('aws-amazon-bedrock-api-key-short-lived', {r['rule'] for r in gate.check(self.repo, rev)['findings']})
    def test_tightened_policy_exact_parsed_values(self):
        parsed = tomllib.loads((gate.BASE / 'trusted-derived.toml').read_text())
        self.assertEqual(hashlib.sha256(json.dumps(parsed, sort_keys=True, separators=(',', ':')).encode()).hexdigest(), '82d10d652f3d34b6a0e9021bde817bb909a63fa28593042455f63121c96e97ae')
        parsed = tomllib.loads((gate.BASE / 'upstream/gitleaks.toml').read_text())
        self.assertEqual(hashlib.sha256(json.dumps(parsed, sort_keys=True, separators=(',', ':')).encode()).hexdigest(), 'a7a30d0d3e61f206188d79f91ce9406dfcd0336b514b1000366a76efdeec394c')
    def test_synthetic_google_key_detected(self):
        value = 'AI' + 'za' + base64.urlsafe_b64encode(hashlib.sha256(b'fabricated Google shape only').digest()).decode()[:35]
        rev = self.commit({'fixture.txt': value})
        self.assertIn('gcp-api-key', {r['rule'] for r in gate.check(self.repo, rev)['findings']})
    def test_policy_key_shape_raw_and_parsed_rejection(self):
        value = 'AI' + 'za' + hashlib.sha256(b'fabricated policy shape only').hexdigest()[:35]
        escaped = ''.join('\\u%04x' % ord(c) for c in value)
        for source in ('# ' + value, 'name = "' + value + '"', 'name = "' + escaped + '"', '"' + escaped + '" = 1'):
            with self.subTest(kind='synthetic-policy'):
                with self.assertRaisesRegex(gate.Error, 'policy-key-shaped-material'):
                    gate.reject_policy_key_shapes(source.encode())
    def test_both_policy_sources_have_no_google_key_shapes(self):
        for rel in ('trusted-derived.toml', 'upstream/gitleaks.toml'):
            raw = (gate.BASE / rel).read_bytes()
            gate.reject_policy_key_shapes(raw)
            rule = next(r for r in tomllib.loads(raw.decode())['rules'] if r['id'] == 'gcp-api-key')
            self.assertNotIn('allowlists', rule)
    def test_policy_invalid_data_fails_closed(self):
        for raw in (b'\xff', b'invalid = ['):
            with self.assertRaisesRegex(gate.Error, 'policy-data-invalid'):
                gate.reject_policy_key_shapes(raw)
    def test_policy_opaque_exception_scope(self):
        values = ['12345678' + '-1234' * 3 + '-123456789abc', hashlib.sha256(b'fabricated opaque exception').hexdigest()[:32]]
        for value in values:
            for field in ('regexes', 'stopwords'):
                for form in (value, '^' + value + '$', '(?:synthetic|' + value + ')'):
                    raw = ('[allowlist]\n' + field + ' = ' + json.dumps([form])).encode()
                    with self.assertRaisesRegex(gate.Error, 'policy-opaque-literal-exception'):
                        gate.reject_policy_key_shapes(raw)
            gate.reject_policy_key_shapes(('description = ' + json.dumps(value)).encode())
        gate.reject_policy_key_shapes(('[allowlist]\nregexes = ' + json.dumps([hashlib.sha256(b'synthetic full digest').hexdigest()])).encode())
    def test_synthetic_allowlist_suppression_removed(self):
        value = 'AI' + 'za' + base64.urlsafe_b64encode(hashlib.sha256(b'fabricated Google shape only').digest()).decode()[:35]
        original = (gate.BASE / 'trusted-derived.toml').read_text()
        offset = original.index('[[rules]]', original.index('id = "gcp-api-key"'))
        controlled = original[:offset] + '[[rules.allowlists]]\nregexes = ' + json.dumps([value]) + '\n\n' + original[offset:]
        config = self.repo.parent / 'synthetic-policy.toml'
        report = self.repo.parent / 'synthetic-report.json'
        ignore = self.repo.parent / 'empty.ignore'; ignore.write_bytes(b'')
        for source, expected in ((controlled, 0), (original, 1)):
            config.write_text(source)
            result = subprocess.run([str(gate.GITLEAKS), 'stdin', '--config', str(config), '--gitleaks-ignore-path', str(ignore), '--ignore-gitleaks-allow', '--redact=100', '--no-banner', '--log-level', 'error', '--report-format', 'template', '--report-template', str(gate.BASE / 'metadata-report.tmpl'), '--report-path', str(report)], input=value.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, env={'PATH': os.defpath, 'HOME': str(self.repo.parent), 'GOMAXPROCS': '2', 'GOMEMLIMIT': '256MiB'})
            self.assertIn(result.returncode, (0, 1))
            rows = json.loads(report.read_text())
            self.assertEqual(sum(row['RuleID'] == 'gcp-api-key' for row in rows), expected)
    def test_clean(self):
        rev = self.commit({'a.py': 'print("hello")\n'})
        report = gate.check(self.repo, rev)
        self.assertEqual(report['detector_status'], 'clean')
        self.assertEqual(report['tree'], self.git('rev-parse', 'HEAD^{tree}'))
        self.assertEqual(len(report['manifest']), 1)
    def test_secret_and_inline_allow_not_trusted(self):
        rev = self.commit({'a.py': f'token = "{SYNTHETIC}" # gitleaks:allow\n'})
        report = gate.check(self.repo, rev)
        self.assertEqual(report['detector_status'], 'findings')
        self.assertNotIn(SYNTHETIC, json.dumps(report))
    def test_hostile_configuration_and_paths(self):
        rev = self.commit({'.gitleaks.toml': '[allowlist]\nregexes=[".*"]\n', '.gitleaksignore': '*\n',
                           'vendor/tests/::error::\nattack.py': SYNTHETIC})
        report = gate.check(self.repo, rev)
        self.assertEqual(report['detector_status'], 'findings')
        rendered = json.dumps(report)
        self.assertNotIn('attack', rendered)
        self.assertNotIn('::error::', rendered)
    def test_worktree_ignored(self):
        rev = self.commit({'a.py': SYNTHETIC})
        (self.repo / 'a.py').write_text('clean')
        self.assertEqual(gate.check(self.repo, rev)['detector_status'], 'findings')
    def test_untracked_ignored(self):
        rev = self.commit({'a.py': 'clean'})
        (self.repo / 'untracked').write_text(SYNTHETIC)
        self.assertEqual(gate.check(self.repo, rev)['detector_status'], 'clean')
    def test_md_remains_stage_a_scope(self):
        rev = self.commit({'a.md': SYNTHETIC, 'a.mdx': SYNTHETIC})
        self.assertEqual(gate.check(self.repo, rev)['manifest'], [])
    def test_nonexact_revision(self):
        self.commit({'a.py': 'clean'})
        with self.assertRaisesRegex(gate.Error, 'exact-object'):
            gate.check(self.repo, 'HEAD')
    def test_binary(self):
        rev = self.commit({'a.bin': b'\0hello'})
        with self.assertRaisesRegex(gate.Error, 'binary-not-covered'):
            gate.check(self.repo, rev)
    def test_encoding(self):
        rev = self.commit({'a.txt': b'\xffhello'})
        with self.assertRaisesRegex(gate.Error, 'encoding-not-covered'):
            gate.check(self.repo, rev)
    def test_archive(self):
        rev = self.commit({'a.zip': 'synthetic not a real archive'})
        with self.assertRaisesRegex(gate.Error, 'archive-not-covered'):
            gate.check(self.repo, rev)
    def test_lfs(self):
        rev = self.commit({'a.txt': 'version https://git-lfs.github.com/spec/v1\n'})
        with self.assertRaisesRegex(gate.Error, 'lfs-pointer'):
            gate.check(self.repo, rev)
    def test_symlink(self):
        os.symlink('missing', self.repo / 'link')
        rev = self.commit({'a.py': 'clean'})
        with self.assertRaisesRegex(gate.Error, 'unsupported-tree-entry'):
            gate.check(self.repo, rev)
    def test_submodule(self):
        rev = self.commit({'a.py': 'clean'})
        self.git('update-index', '--add', '--cacheinfo', '160000,' + rev + ',submodule')
        self.git('commit', '-qm', 'synthetic gitlink')
        with self.assertRaisesRegex(gate.Error, 'unsupported-tree-entry'):
            gate.check(self.repo, self.git('rev-parse', 'HEAD'))
    def test_budget(self):
        rev = self.commit({'a.txt': '1234567890'})
        with patch.object(gate, 'MAX_FILE', 5):
            with self.assertRaisesRegex(gate.Error, 'size-limit'):
                gate.check(self.repo, rev)
    def test_scanner_failure(self):
        rev = self.commit({'a.py': 'clean'})
        # run_git uses Popen, not run; only the detector invocation is replaced.
        with patch.object(gate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2)):
            with self.assertRaisesRegex(gate.Error, 'scanner-failed'):
                gate.check(self.repo, rev)
    def test_supported_text_gate_clean(self):
        rev = self.commit({'a.py': 'clean'})
        report = gate.check(self.repo, rev)
        self.assertEqual(report['status'], 'clean')
    def test_path_sensitive_positive_control(self):
        # Same synthetic bytes: the official Terraform rule requires tf/hcl path.
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            export = temp / 'snapshot'
            export.mkdir()
            original = export / 'main.tf'
            original.write_text('password = "a1B2c3D4e5"\n')
            item = {'file_id': '0' * 64, 'blob': '0' * 40}
            original_rows = gate.scan_export(export, {str(original): item, original.name: item}, temp)
            self.assertIn('hashicorp-tf-password', {r['rule'] for r in original_rows})
            opaque = export / 'opaque.txt'
            original.rename(opaque)
            opaque_rows = gate.scan_export(export, {str(opaque): item, opaque.name: item}, temp)
            self.assertNotIn('hashicorp-tf-password', {r['rule'] for r in opaque_rows})
    def test_path_specific_rules(self):
        rev = self.commit({
            'infra/main.tf': 'password = "a1B2c3D4e5"\n',
            'packages/nuget.config': '<add key="ClearTextPassword" value="A1b2C3d4E5f6" />',
            'deploy/secret.yaml': 'apiVersion: v1\nkind: Secret\ndata:\n  password: ' + base64.b64encode(bytes(range(97, 113))).decode() + '\n',
            'keys/synthetic.pfx': 'synthetic container placeholder, no real key',
            'src/a.php': "'secret_key' => 'sk_" + 'Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op5'[:29] + "'",
        })
        report = gate.check(self.repo, rev)
        rules = {r['rule'] for r in report['findings']}
        self.assertTrue({'hashicorp-tf-password', 'nuget-config-password', 'kubernetes-secret-yaml', 'pkcs12-file', 'freemius-secret-key'} <= rules, rules)
        self.assertEqual(report['status'], 'findings')
    def test_default_path_exclusions_removed(self):
        paths = ['vendor/github.com/pkg/x.py', 'node_modules/pkg/x.js', 'package-lock.json', 'images/a.svg', '.gitleaks.toml', 'go.sum']
        rev = self.commit({p: SYNTHETIC for p in paths})
        rows = gate.check(self.repo, rev)['findings']
        self.assertEqual({r['file_id'] for r in rows}, {gate.digest(p.encode()) for p in paths})
    def test_gitignore_and_exact_fingerprint_ignore_not_trusted(self):
        rev = self.commit({'ignored/token.py': SYNTHETIC, '.gitignore': '*\n',
                           '.gitleaksignore': 'ignored/token.py:github-pat:1\n'})
        self.assertEqual(gate.check(self.repo, rev)['status'], 'findings')
    def test_path_only_empty_container(self):
        rev = self.commit({'empty.p12': ''})
        # Engine skips empty files: adapter must handle path-only PKCS12 itself.
        self.assertEqual(gate.check(self.repo, rev)['status'], 'findings')
    def test_application_magic_utf8_is_incomplete(self):
        rev = self.commit({'a.txt': '%PDF-1.4\nsynthetic content\n'})
        with self.assertRaisesRegex(gate.Error, 'coverage-incomplete'):
            gate.check(self.repo, rev)
    def test_timeout(self):
        rev = self.commit({'a.py': 'clean'})
        with patch.object(gate.subprocess, 'run', side_effect=subprocess.TimeoutExpired([], 60)):
            with self.assertRaisesRegex(gate.Error, 'scanner-incomplete'):
                gate.check(self.repo, rev)
    def test_blob_corruption(self):
        rev = self.commit({'a.py': 'clean'})
        real = gate.git.run_git
        def corrupt(repo, args, **kwargs):
            out = real(repo, args, **kwargs)
            return out.replace(b'clean', b'wrong') if '--batch' in args else out
        with patch.object(gate.git, 'run_git', side_effect=corrupt):
            with self.assertRaisesRegex(gate.Error, 'blob-digest-mismatch'):
                gate.check(self.repo, rev)
    def test_report_parse_failure(self):
        rev = self.commit({'a.py': 'clean'})
        def malformed(cmd, **kwargs):
            Path(cmd[cmd.index('--report-path') + 1]).write_text('not-json')
            return subprocess.CompletedProcess(cmd, 0)
        with patch.object(gate.subprocess, 'run', side_effect=malformed):
            with self.assertRaisesRegex(gate.Error, 'scanner-incomplete'):
                gate.check(self.repo, rev)
    def test_detector_rules_unchanged(self):
        upstream = tomllib.loads((gate.BASE / 'upstream/gitleaks.toml').read_text())
        derived = tomllib.loads((gate.BASE / 'trusted-derived.toml').read_text())
        self.assertEqual(len(upstream['rules']), 222)
        self.assertNotIn('paths', derived['allowlist'])
        for before, after in zip(upstream['rules'], derived['rules']):
            before = dict(before)
            before['allowlists'] = [a for a in before.get('allowlists', []) if 'paths' not in a]
            if not before['allowlists']:
                del before['allowlists']
            self.assertEqual(before, after)
    def test_missing_coverage_fails_closed(self):
        rev = self.commit({'a.py': 'clean'})
        def empty(cmd, **kwargs):
            Path(cmd[cmd.index('--report-path') + 1]).write_text('[]')
            return subprocess.CompletedProcess(cmd, 0)
        with patch.object(gate.subprocess, 'run', side_effect=empty):
            with self.assertRaisesRegex(gate.Error, 'coverage-incomplete'):
                gate.check(self.repo, rev)
    def test_cli_findings_redaction(self):
        rev = self.commit({'::error::\nsource.py': SYNTHETIC})
        proc = subprocess.run(['python3', '-B', str(gate.BASE / 'gate.py'), '--repo', str(self.repo), '--revision', rev], capture_output=True)
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn(SYNTHETIC.encode(), proc.stdout + proc.stderr)
        self.assertNotIn(b'::error::', proc.stdout + proc.stderr)
        self.assertEqual(proc.stderr, b'')
    def test_pinned_path_predicates_complete(self):
        policy = tomllib.loads((gate.BASE / 'trusted-derived.toml').read_text())
        self.assertEqual({r['id']: r['path'] for r in policy['rules'] if 'path' in r}, gate.PATH_PREDICATES)
    def test_fragment_boundaries_and_large_single_line(self):
        positions = [81808, 89980, 99980, 124980, 163616, 900000]
        files = {'boundary-' + str(pos) + '.txt': b' ' * pos + ('"' + SYNTHETIC + '"').encode() + b' end' for pos in positions}
        rev = self.commit(files)
        report = gate.check(self.repo, rev)
        self.assertEqual(report['status'], 'findings')
        self.assertGreater(report['window_count'], 10)
        self.assertEqual({r['file_id'] for r in report['findings'] if r['rule'] == 'github-pat'}, {gate.digest(p.encode()) for p in files})
    def test_large_multiline_utf8(self):
        raw = ('中文 synthetic line\n' * 20000) + 'token = "' + SYNTHETIC + '"\n'
        rev = self.commit({'unicode.txt': raw})
        report = gate.check(self.repo, rev)
        self.assertTrue(any(r['line'] == 20001 and r['rule'] == 'github-pat' for r in report['findings']))
    def test_twenty_mib_text(self):
        line = b'normal source text\n'
        raw = line * (gate.MAX_FILE // len(line)) + b' ' * (gate.MAX_FILE % len(line))
        rev = self.commit({'large.txt': raw})
        report = gate.check(self.repo, rev)
        self.assertEqual(report['status'], 'clean')
        self.assertGreater(report['manifest'][0]['bytes'], 12_564_863)
    def test_window_utf8_contiguous_overlap(self):
        raw = ('中' * 100000).encode()
        previous_end = 0
        for start, chunk in gate.windows(raw):
            chunk.decode('utf8')
            self.assertEqual(chunk, raw[start:start + len(chunk)])
            if previous_end:
                self.assertGreaterEqual(previous_end - start, gate.OVERLAP_BYTES)
            previous_end = start + len(chunk)
        self.assertEqual(previous_end, len(raw))
    def test_read_gap_metadata_rejected(self):
        rev = self.commit({'a.txt': 'normal content'})
        real = gate.subprocess.run
        def truncate_report(cmd, **kwargs):
            result = real(cmd, **kwargs)
            report_path = Path(cmd[cmd.index('--report-path') + 1])
            rows = json.loads(report_path.read_text())
            for row in rows:
                if row['RuleID'] == 'adapter-coverage':
                    row['EndColumn'] -= 1
            report_path.write_text(json.dumps(rows))
            return result
        with patch.object(gate.subprocess, 'run', side_effect=truncate_report):
            with self.assertRaisesRegex(gate.Error, 'coverage-range-mismatch'):
                gate.check(self.repo, rev)
    def test_export_mutation_rejected(self):
        rev = self.commit({'a.txt': 'normal content'})
        real = gate.scan_export
        def mutate(export, mapping, temp, **kwargs):
            result = real(export, mapping, temp, **kwargs)
            if not kwargs.get('coverage'):
                (export / next(iter(mapping))).write_text('different bytes')
            return result
        with patch.object(gate, 'scan_export', side_effect=mutate):
            with self.assertRaisesRegex(gate.Error, 'export-integrity-mismatch'):
                gate.check(self.repo, rev)
    def test_newline_only_and_unicode_edges(self):
        rev = self.commit({'newlines.txt': '\n' * 200000, 'edges.txt': '\n中文\nend\n\n'})
        self.assertEqual(gate.check(self.repo, rev)['status'], 'clean')
    def test_duplicate_partial_read_rows_rejected(self):
        rev = self.commit({'a.txt': 'first line\nlast line'})
        real = gate.subprocess.run
        def duplicate(cmd, **kwargs):
            result = real(cmd, **kwargs)
            report_path = Path(cmd[cmd.index('--report-path') + 1])
            rows = json.loads(report_path.read_text())
            rows += [r for r in rows if r['RuleID'] == 'adapter-coverage']
            report_path.write_text(json.dumps(rows))
            return result
        with patch.object(gate.subprocess, 'run', side_effect=duplicate):
            with self.assertRaisesRegex(gate.Error, 'coverage-incomplete'):
                gate.check(self.repo, rev)
    def test_single_chinese_rune_tail(self):
        rev = self.commit({'unicode.txt': '中'})
        self.assertEqual(gate.check(self.repo, rev)['status'], 'clean')
        self.assertEqual(gate.coverage_tail_signature('中'.encode()), (1, 1, 1, 3))
    def test_ascii_plus_chinese_tail(self):
        rev = self.commit({'unicode.txt': 'ASCII中'})
        self.assertEqual(gate.check(self.repo, rev)['status'], 'clean')
        self.assertEqual(gate.coverage_tail_signature('ASCII中'.encode()), (1, 1, 6, 8))
    def test_ascii_plus_emoji_tail(self):
        rev = self.commit({'unicode.txt': 'ASCII😀'})
        self.assertEqual(gate.check(self.repo, rev)['status'], 'clean')
        self.assertEqual(gate.coverage_tail_signature('ASCII😀'.encode()), (1, 1, 6, 9))
    def test_chinese_plus_lf_tail(self):
        rev = self.commit({'unicode.txt': '中\n\n'})
        self.assertEqual(gate.check(self.repo, rev)['status'], 'clean')
    def test_multiline_utf8_final_rune(self):
        rev = self.commit({'unicode.txt': 'first\n中文\nlast😀'})
        self.assertEqual(gate.check(self.repo, rev)['status'], 'clean')
    def test_multiwindow_chinese_tail(self):
        rev = self.commit({'unicode.txt': '中' * 100000, 'ascii-ended.txt': '中' * 100000 + 'ASCII'})
        report = gate.check(self.repo, rev)
        self.assertEqual(report['status'], 'clean')
        self.assertGreater(report['window_count'], 1)
    def test_multiwindow_utf8_secret_detection(self):
        rev = self.commit({'unicode.txt': '中' * 40000 + '"' + SYNTHETIC + '"' + '😀' * 20000})
        self.assertEqual(gate.check(self.repo, rev)['status'], 'findings')
    def test_same_pass_read_denial(self):
        rev = self.commit({'fixture.txt': SYNTHETIC})
        self.assertEqual(gate.check(self.repo, rev)['status'], 'findings')
        real = gate.subprocess.run
        def deny(cmd, **kwargs):
            target = Path(kwargs['cwd']) / 'window-0/fixture.txt'
            target.chmod(0)
            try:
                return real(cmd, **kwargs)
            finally:
                target.chmod(0o600)
        with patch.object(gate.subprocess, 'run', side_effect=deny):
            with self.assertRaisesRegex(gate.Error, 'coverage-incomplete'):
                gate.check(self.repo, rev)
    def test_generic_key_not_suppressed_by_control(self):
        rev = self.commit({'fixture.txt': 'api_key = \"' + hashlib.sha256(b'synthetic generic fixture').hexdigest() + '\"'})
        self.assertIn('generic-api-key', {r['rule'] for r in gate.check(self.repo, rev)['findings']})
    def test_encoded_secret_with_same_pass_controls(self):
        encoded = base64.b64encode(SYNTHETIC.encode()).decode()
        rev = self.commit({'fixture.txt': 'encoded = "' + encoded + '"'})
        self.assertIn('github-pat', {r['rule'] for r in gate.check(self.repo, rev)['findings']})
    def test_content_allowlist_does_not_suppress_controls(self):
        rev = self.commit({'false.txt': 'false', 'asterisks.txt': '*', 'alphabet.txt': 'abcdefghijklmnopqrstuvwxyz'})
        self.assertEqual(gate.check(self.repo, rev)['status'], 'clean')
    def test_allowlist_targets_original_rules_only(self):
        upstream = tomllib.loads((gate.BASE / 'upstream/gitleaks.toml').read_text())
        derived = tomllib.loads((gate.BASE / 'trusted-derived.toml').read_text())
        original_allow = dict(upstream['allowlist'])
        del original_allow['paths']
        derived_allow = dict(derived['allowlist'])
        targets = derived_allow.pop('targetRules')
        self.assertEqual(targets, [r['id'] for r in upstream['rules']])
        self.assertEqual(original_allow, derived_allow)
        self.assertEqual(len(derived['rules']), 224)
    def test_metadata_report_excludes_match_and_secret(self):
        rev = self.commit({'fixture.txt': SYNTHETIC})
        real = gate.subprocess.run
        observed = []
        def inspect(cmd, **kwargs):
            self.assertEqual(cmd[cmd.index('--timeout') + 1], '0')
            result = real(cmd, **kwargs)
            raw = Path(cmd[cmd.index('--report-path') + 1]).read_text()
            self.assertNotIn(SYNTHETIC, raw)
            for row in json.loads(raw):
                self.assertEqual(set(row), {'File', 'RuleID', 'StartLine', 'EndLine', 'StartColumn', 'EndColumn', 'Tags'})
            observed.append(True)
            return result
        with patch.object(gate.subprocess, 'run', side_effect=inspect):
            self.assertEqual(gate.check(self.repo, rev)['status'], 'findings')
        self.assertEqual(len(observed), 1)
    def test_malformed_tags_and_boolean_ranges_rejected(self):
        rev = self.commit({'fixture.txt': 'normal text'})
        real = gate.subprocess.run
        for field, value in [('Tags', False), ('Tags', 0), ('Tags', ''), ('Tags', {}), ('StartColumn', True)]:
            with self.subTest(field=field, value_type=type(value).__name__):
                def malformed(cmd, **kwargs):
                    result = real(cmd, **kwargs)
                    target = Path(cmd[cmd.index('--report-path') + 1])
                    rows = json.loads(target.read_text())
                    rows[0][field] = value
                    target.write_text(json.dumps(rows))
                    return result
                with patch.object(gate.subprocess, 'run', side_effect=malformed):
                    with self.assertRaisesRegex(gate.Error, 'scanner-report-invalid'):
                        gate.check(self.repo, rev)
    def test_cli_invalid_argument_redaction(self):
        proc = subprocess.run(['python3', str(gate.BASE / 'gate.py'), '--private=' + SYNTHETIC], capture_output=True)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn(SYNTHETIC.encode(), proc.stdout + proc.stderr)


CI_PATH = GATE_PATH.with_name('ci.py')
ci_spec = importlib.util.spec_from_file_location('secret_ci', CI_PATH)
ci = importlib.util.module_from_spec(ci_spec)
exec(compile(CI_PATH.read_bytes(), str(CI_PATH), 'exec'), ci.__dict__)

class CITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-ci-')
        self.root = Path(self.temp.name)
        self.event_path = self.root / 'event.json'
        self.revision = 'a' * 40
        self.event = {'repository': {'full_name': ci.REPOSITORY, 'private': False, 'visibility': 'public'}, 'after': self.revision}
        self.env = {'GITHUB_REPOSITORY': ci.REPOSITORY, 'GITHUB_EVENT_PATH': str(self.event_path), 'GITHUB_SHA': self.revision, 'GITHUB_EVENT_NAME': 'push'}
    def tearDown(self): self.temp.cleanup()
    def validate(self):
        self.event_path.write_text(json.dumps(self.event))
        with patch.dict(os.environ, self.env, clear=True): return ci.public_event()
    def test_public_push_exact_commit(self): self.assertEqual(self.validate(), self.revision)
    def test_private_missing_or_wrong_repository_rejected(self):
        for change in ({'private': True}, {'private': None}, {'visibility': 'internal'}, {'full_name': 'synthetic/other'}):
            with self.subTest(change=change):
                old = dict(self.event['repository']); self.event['repository'].update(change)
                with self.assertRaises(ci.Failure): self.validate()
                self.event['repository'] = old
    def test_event_commit_mismatch_rejected(self):
        self.event['after'] = 'b'*40
        with self.assertRaises(ci.Failure): self.validate()
    def test_public_pull_request_merge_commit(self):
        self.env['GITHUB_EVENT_NAME'] = 'pull_request'
        self.event['pull_request'] = {'merge_commit_sha': self.revision}
        self.assertEqual(self.validate(), self.revision)
        self.event['pull_request']['merge_commit_sha'] = None
        with self.assertRaises(ci.Failure): self.validate()
    def test_privileged_event_rejected(self):
        self.env['GITHUB_EVENT_NAME'] = 'pull_request_target'
        with self.assertRaises(ci.Failure): self.validate()
    def test_new_session_child_reaped_after_timeout(self):
        pidfile = self.root / 'child-pid'; real = ci.subprocess.Popen
        code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True); open(sys.argv[1],'w').write(str(p.pid));time.sleep(30)"
        def fake(cmd, **kwargs): return real([sys.executable, '-c', code, str(pidfile)], **kwargs)
        with patch.object(ci, 'FIXTURE_SECONDS', 1), patch.object(ci.subprocess, 'Popen', side_effect=fake):
            with self.assertRaisesRegex(ci.Failure, 'whole-job-timeout'): ci.supervise('fixtures', self.revision)
        self.assertTrue(pidfile.exists())
        with self.assertRaises(ProcessLookupError): os.kill(int(pidfile.read_text()), 0)

if __name__ == '__main__':
    unittest.main(verbosity=2)
