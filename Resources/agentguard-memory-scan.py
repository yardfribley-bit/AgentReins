#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentGuard 记忆体敏感信息扫描器

扫描 agent 记忆体（Kiro / Claude / Cursor / Codex 等）是否保存了密钥、令牌、私钥、
数据库连接串等敏感信息。复用了 AgentSpec 的「运行时强制」思想，但作用在「静态记忆审计」层。

覆盖的 Kiro 记忆落盘位置：
  ~/.kiro/crew/workspace/memory/   全局记忆（Markdown + SQLite 语义/情景记忆）
  ~/.kiro/knowledge/memory/**      知识库（Markdown）
  ~/.kiro/steering/                规则（Markdown）
  ~/.kiro/sessions/cli/            CLI 会话（.json/.jsonl）
  ~/.agent-memory/                 Kiro MCP 记忆（若启用）
  ~/Library/Application Support/Kiro/  IDE 执行日志（含完整工具调用，最易泄密）
  ~/.claude ~/.cursor ~/.codex     其他 agent 记忆

零依赖（仅 Python 标准库，含 sqlite3）。
用法：
  python3 agentguard-memory-scan.py                 # 扫描默认目标
  python3 agentguard-memory-scan.py --scan-cwd      # 额外扫描当前目录及上层的 .kiro
  python3 agentguard-memory-scan.py --targets /path/a /path/b
  python3 agentguard-memory-scan.py --selftest      # 自测（造含密钥样本，验证检测）
  python3 agentguard-memory-scan.py --json          # 输出机器可读 JSON
退出码：发现敏感信息返回 1（可作 CI/护栏门禁），--no-fail 则恒为 0。
"""
import os
import re
import sys
import json
import sqlite3
import argparse
import datetime

HOME = os.path.expanduser("~")

DEFAULT_TARGETS = [
    os.path.join(HOME, ".kiro"),
    os.path.join(HOME, ".agent-memory"),
    os.path.join(HOME, "Library", "Application Support", "Kiro"),
    os.path.join(HOME, ".claude"),
    os.path.join(HOME, ".cursor"),
    os.path.join(HOME, ".codex"),
]

# 默认敏感信息正则（标准库 re，零依赖）。用户可通过 --rules-file / --rules-json 覆盖。
SECRET_PATTERNS = [
    ("aws_ak", "AWS Access Key ID", "high", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_sk", "AWS Secret Access Key", "high", re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("openai", "OpenAI API Key", "high", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("anthropic", "Anthropic API Key", "high", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("github", "GitHub Token", "high", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}")),
    ("google", "Google API Key", "high", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("stripe", "Stripe Secret Key", "high", re.compile(r"sk_live_[0-9a-zA-Z]{16,}")),
    ("slack", "Slack Token", "high", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("privkey", "Private Key Block", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("dbconn", "DB Connection String", "high", re.compile(r"(?i)(postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:]+:[^\s@]{3,}@")),
    ("generic_secret", "Generic Secret Assignment", "medium",
     re.compile(r"(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*['\"][A-Za-z0-9_\-+/=!@#$%^&*()]{12,}['\"]")),
]


def default_rules():
    """默认规则，JSON 可配格式 [{id,name,enabled,pattern,description,severity}]"""
    return [{"id": rid, "name": name, "enabled": True, "pattern": pat.pattern,
             "description": name, "severity": sev}
            for rid, name, sev, pat in SECRET_PATTERNS]


def compile_rules(items):
    """把用户规则列表编译成扫描可用的 (name, compiled_re, meta) 列表。"""
    out = []
    for it in items:
        if not it.get("enabled", True):
            continue
        pat = it.get("pattern", "")
        if not pat:
            continue
        try:
            rx = re.compile(pat)
        except re.error as e:
            sys.stderr.write("[warn] 规则 %s 正则无效，跳过: %s\n" % (it.get("id", "?"), e))
            continue
        out.append((it.get("name", "unnamed"), rx, it))
    return out


def load_rules(args):
    """从命令行参数加载规则；未指定则使用内置默认。"""
    if args.rules_json:
        try:
            items = json.loads(args.rules_json)
            if isinstance(items, dict):
                items = items.get("rules", [])
        except Exception as e:
            sys.stderr.write("[warn] --rules-json 解析失败，使用默认规则: %s\n" % e)
            items = default_rules()
    elif args.rules_file and os.path.exists(args.rules_file):
        try:
            with open(args.rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            items = data if isinstance(data, list) else data.get("rules", [])
        except Exception as e:
            sys.stderr.write("[warn] --rules-file 解析失败，使用默认规则: %s\n" % e)
            items = default_rules()
    else:
        items = default_rules()
    return compile_rules(items)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".build", "Frameworks", "Caches"}
TEXT_EXT = {".md", ".markdown", ".txt", ".text", ".json", ".jsonl", ".yaml", ".yml",
            ".toml", ".env", ".py", ".js", ".ts", ".tsx", ".sh", ".cfg", ".ini", ".log",
            ".csv", ".xml", ".sql"}
SQLITE_EXT = {".db", ".sqlite", ".sqlite3"}
MAX_FILE = 5 * 1024 * 1024  # 5MB，避免扫大二进制


def redact(s):
    if len(s) <= 8:
        return "****"
    return s[:4] + "…" + s[-2:]


def scan_text(content, src, findings, patterns, line_offset=0, src_kind="file"):
    """返回本次新增的命中数（供 inventory 聚合）。"""
    before = len(findings)
    for name, pat, meta in patterns:
        for m in pat.finditer(content):
            pos = m.start()
            line = line_offset + content.count("\n", 0, pos) + 1
            findings.append({
                "type": name,
                "rule_id": meta.get("id", name),
                "severity": meta.get("severity", "high"),
                "src": src,
                "src_kind": src_kind,
                "line": line,
                "preview": redact(m.group(0)),
                "match": m.group(0),   # 原始命中文本，供 App 精确打码/删行
            })
    return len(findings) - before


def kind_of(ext):
    if ext in (".md", ".markdown"):
        return "md"
    if ext in (".json", ".jsonl"):
        return "jsonl"
    if ext in SQLITE_EXT:
        return "sqlite"
    return "text"


def agent_of_root(root):
    r = os.path.expanduser(root)
    if "Application Support/Kiro" in r or ".kiro" in r or ".agent-memory" in r:
        return "Kiro"
    if ".claude" in r:
        return "Claude"
    if ".cursor" in r:
        return "Cursor"
    if ".codex" in r:
        return "Codex"
    return "Other"


def scan_sqlite(path, findings, patterns):
    count = 0
    try:
        con = sqlite3.connect(path)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        for t in tables:
            try:
                cur.execute("SELECT * FROM '%s'" % t.replace("'", "''"))
                for row in cur.fetchall():
                    for val in row:
                        if isinstance(val, str) and len(val) > 3:
                            count += scan_text(val, path, findings, patterns,
                                              src_kind="sqlite:%s" % t)
            except Exception:
                continue
        con.close()
    except Exception:
        pass
    return count


def scan_file(path, findings, patterns, inventory, agent, root):
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size > MAX_FILE:
        return
    ext = os.path.splitext(path)[1].lower()
    kind = kind_of(ext)
    if ext in SQLITE_EXT:
        count = scan_sqlite(path, findings, patterns)
    elif ext in TEXT_EXT or ext == "":
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            return
        count = scan_text(content, path, findings, patterns)
    else:
        return  # 二进制等非文本：不进 inventory
    new = findings[len(findings) - count:] if count else []
    types = sorted({f["type"] for f in new})
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        rel = path
    inventory[path] = {
        "agent": agent,
        "path": path,
        "rel": rel,
        "size": size,
        "kind": kind,
        "sensitive_count": count,
        "sensitive_types": types,
    }


def scan_target(root, findings, patterns, inventory, agent):
    if not os.path.exists(root):
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            scan_file(os.path.join(dirpath, fn), findings, patterns, inventory, agent, root)


def collect_targets(extra, scan_cwd):
    # 显式指定 --targets 时只扫用户给定路径；不指定才扫默认 agent 记忆根
    targets = list(extra) if extra else list(DEFAULT_TARGETS)
    if scan_cwd:
        here = os.getcwd()
        for base in (here, os.path.dirname(here), os.path.dirname(os.path.dirname(here))):
            kd = os.path.join(base, ".kiro")
            if os.path.isdir(kd) and kd not in targets:
                targets.append(kd)
    return targets


def run(extra, scan_cwd, patterns=None):
    if patterns is None:
        patterns = compile_rules(default_rules())
    findings = []
    inventory = {}
    targets = collect_targets(extra, scan_cwd)
    for t in targets:
        if os.path.exists(t):
            scan_target(t, findings, patterns, inventory, agent_of_root(t))
    return findings, inventory, targets


def selftest():
    import tempfile
    import shutil
    d = tempfile.mkdtemp(prefix="agr_mem_selftest_")
    print("AgentGuard 记忆扫描自检（造含密钥样本）\n" + "-" * 50)
    samples = {
        "preferences.md": "I prefer Slack. aws_secret_access_key = 'AKIAIOSFODNN7EXAMPLEFAKEKEY1234567890XYZ'\n",
        "history/2026-09-03.md": "user gave openai key sk-fake1234567890abcdefghijklmnop\n",
        "knowledge/topic.md": "db: postgresql://admin:SuperSecretPass@db.example.com:5432/app\n",
        "sessions/cli/run.jsonl": '{"role":"user","content":"my github token ghp_' + ("a" * 36) + '"}\n',
        "steering/memory.md": "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
        "clean.md": "just some notes, no secrets here.\n",
    }
    os.makedirs(os.path.join(d, "history"), exist_ok=True)
    os.makedirs(os.path.join(d, "knowledge"), exist_ok=True)
    os.makedirs(os.path.join(d, "sessions", "cli"), exist_ok=True)
    os.makedirs(os.path.join(d, "steering"), exist_ok=True)
    for rel, txt in samples.items():
        with open(os.path.join(d, rel), "w") as f:
            f.write(txt)
    findings = []
    patterns = compile_rules(default_rules())
    inv = {}
    scan_target(d, findings, patterns, inv, "Kiro")  # 仅扫描样本，不碰 HOME 下的真实 agent 记忆
    # 期望：在 clean.md 之外都发现；至少覆盖 AWS/OpenAI/DB/PrivateKey/GitHub
    expected = {"AWS Access Key ID", "AWS Secret Access Key", "OpenAI API Key",
                "DB Connection String", "Private Key Block", "GitHub Token"}
    found_types = {f["type"] for f in findings}
    clean_hits = [f for f in findings if f["src"].endswith("clean.md")]
    ok = expected.issubset(found_types) and not clean_hits
    print("期望类型全部命中: %s" % expected.issubset(found_types))
    print("clean.md 无误报: %s" % (not clean_hits))
    for f in findings:
        print("  [+] %s @ %s : %s" % (f["type"], os.path.relpath(f["src"], d), f["preview"]))
    shutil.rmtree(d, ignore_errors=True)
    print("-" * 50 + ("\n自检通过 ✅" if ok else "\n自检失败 ❌"))
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description="AgentGuard 记忆体敏感信息扫描器")
    ap.add_argument("--targets", nargs="*", default=[], help="额外扫描目录")
    ap.add_argument("--scan-cwd", action="store_true", help="额外扫描当前目录及上层的 .kiro")
    ap.add_argument("--selftest", action="store_true", help="自测（造含密钥样本）")
    ap.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    ap.add_argument("--no-fail", action="store_true", help="即使发现也不返回非零退出码")
    ap.add_argument("--rules-file", help="规则配置文件(JSON)，格式 [{id,name,enabled,pattern,description,severity}]")
    ap.add_argument("--rules-json", help="规则配置 JSON 字符串（与 --rules-file 二选一）")
    args = ap.parse_args()

    if args.selftest:
        selftest()

    patterns = load_rules(args)
    findings, inventory, targets = run(args.targets, args.scan_cwd, patterns=patterns)
    ts = datetime.datetime.now().isoformat(timespec="seconds")

    if args.json:
        print(json.dumps({"ts": ts, "targets": targets, "count": len(findings),
                          "findings": findings, "inventory": list(inventory.values())},
                         ensure_ascii=False, indent=2))
    else:
        print("AgentGuard 记忆体扫描")
        print("扫描目标: %s" % ", ".join(targets))
        print("发现敏感信息: %d 处\n" % len(findings))
        by_type = {}
        for f in findings:
            by_type.setdefault(f["type"], []).append(f)
        for t, lst in sorted(by_type.items(), key=lambda kv: -len(kv[1])):
            print("[%s] ×%d" % (t, len(lst)))
            for f in lst[:5]:
                rel = os.path.relpath(f["src"], HOME)
                print("    %s:%s  %s" % (rel, f["line"], f["preview"]))
            if len(lst) > 5:
                print("    … 其余 %d 处略" % (len(lst) - 5))

    # 审计日志
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "agentguard_memory_scan.jsonl")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            for rec in findings:
                f.write(json.dumps({"ts": ts, **rec}, ensure_ascii=False) + "\n")
    except OSError:
        pass

    if findings and not args.no_fail:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
