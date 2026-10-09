#!/usr/bin/env python3
"""Independent acceptance oracle. Does not import the producer fixture."""
import argparse, hashlib, json, pathlib
parser = argparse.ArgumentParser()
parser.add_argument('--root', required=True, type=pathlib.Path)
parser.add_argument('--run', required=True)
a = parser.parse_args()
if not a.run.replace('-', '').replace('_', '').isalnum(): parser.error('invalid run ID')
directory = a.root.resolve() / 'output' / a.run
raw = (directory / 'weather.json').read_bytes()
data = json.loads(raw)
expected = [('2026-10-10', 19, 24, 70), ('2026-10-11', 18, 23, 20), ('2026-10-12', 19, 25, 10)]
assert data['city'] == '上海'
assert [(d['date'], d['low'], d['high'], d['rain']) for d in data['days']] == expected
report_bytes = (directory / 'report.md').read_bytes()
report = report_bytes.decode('utf-8')
assert f'验收标记：{a.run}' in report
for date, low, high, rain in expected:
    advice = '携带雨具' if rain >= 50 else '适合户外'
    assert f'| {date} | {low}–{high}℃ | {rain}% | {advice} |' in report
assert '数据来源：http://127.0.0.1:' in report
requests = [json.loads(line) for line in (a.root / 'server.jsonl').read_text().splitlines()]
requests = [r for r in requests if r['target'].endswith('?run=' + a.run)]
assert [(r['status'], r['attempt']) for r in requests] == [(429, 1), (200, 2)]
assert requests[1]['body_sha256'] == hashlib.sha256(raw).hexdigest()
print(json.dumps({'run': a.run, 'verified': True, 'requests': [429, 200], 'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [directory / 'weather.json', directory / 'report.md']}}, ensure_ascii=False))
