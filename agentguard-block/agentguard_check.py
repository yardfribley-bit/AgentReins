#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentGuard 拦截器核心（OS 执行边界的 PATH-shim 版）。

这是监测 MVP 的下一步：从「只看不拦」升级为「能拦 / 能问 / 可放行」。

做法：把 rm / cat / curl / wget / git / bash 等命令替换成 shim（见 shims/），
shim 调用本脚本按 rules.json 的命令层规则判定处置：

  allow            -> 执行真实命令（放行）
  allow(白名单)    -> 用户此前允许过，自动放行并审计
  block            -> 直接拒绝 + 审计 + 通知（高危破坏性，如 rm -rf、curl|bash）
  ask              -> 弹窗询问用户；无 GUI（如本沙箱）时安全默认拒绝（如读密钥、git 强推）

真实命令通过绝对路径执行，避免再次命中 shim（不会死循环）。

注意：
- PATH-shim 只覆盖我们 shim 的二进制，对 GUI agent（Cursor 原生 GUI）不通用；
  生产级通用拦截见 agentguard-esf/（Endpoint Security Framework 系统扩展）。
- `curl ... | bash` 这种「下载即执行」管道发生在 shell 层，curl 自身 argv 看不到 `| bash`，
  因此由 bash shim 检查 `-c` 脚本体来捕获（命中 curl_pipe_bash 规则直接 block）。
"""
import sys
import os
import re
import json
import subprocess
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(HERE, "..", "agentguard", "rules.json")
AUDIT = os.path.join(HERE, "agentguard_block_audit.jsonl")
WHITELIST = os.path.join(HERE, "agentguard_block_whitelist.jsonl")

# 真实二进制绝对路径（绕过 shim，避免回环）
REAL = {
    "rm": "/bin/rm",
    "cat": "/bin/cat",
    "curl": "/usr/bin/curl",
    "wget": "/usr/bin/wget",
    "git": "/usr/bin/git",
    "bash": "/bin/bash",
    "sh": "/bin/sh",
}

# MVP 处置映射：规则命中后怎么办
BLOCK = {"destructive_rm", "curl_pipe_bash"}   # 直接拦截（高危破坏性）
ASK = {"read_secret", "git_force_push"}        # 弹窗询问（敏感但非必然恶意）


# --------------------------------------------------------------------------- #
# 规则 / 白名单
# --------------------------------------------------------------------------- #
def load_rules():
    with open(RULES_PATH, encoding="utf-8") as f:
        return json.load(f)


def in_whitelist(cmd, argstr):
    if not os.path.exists(WHITELIST):
        return False
    sig = f"{cmd}\t{argstr}"
    try:
        with open(WHITELIST, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line == sig:
                    return True
    except OSError:
        return False
    return False


def add_whitelist(cmd, argstr):
    sig = f"{cmd}\t{argstr}"
    try:
        # 已存在则跳过（去重）
        if os.path.exists(WHITELIST):
            with open(WHITELIST, encoding="utf-8") as f:
                if sig in {ln.strip() for ln in f}:
                    return True
        with open(WHITELIST, "a", encoding="utf-8") as f:
            f.write(sig + "\n")
        return True
    except OSError:
        return False


def decide(cmd, argstr):
    """返回 (decision, rule, whitelisted)。decision ∈ allow/block/ask。"""
    full = f"{cmd} {argstr}"
    for r in load_rules()["rules"]:
        if r.get("kind") != "cmd":
            continue
        if re.search(r["pattern"], full, re.I):
            if r["id"] in BLOCK:
                return "block", r, False
            if r["id"] in ASK:
                # 白名单命中则自动放行（用户此前允许过）
                if in_whitelist(cmd, argstr):
                    return "allow", r, True
                return "ask", r, False
    return "allow", None, False


# --------------------------------------------------------------------------- #
# 审计 / 通知 / 询问
# --------------------------------------------------------------------------- #
def audit(cmd, argstr, decision, rule_id, note=""):
    rec = {"ts": datetime.datetime.now().isoformat(timespec="seconds"),
           "cmd": cmd, "args": argstr, "decision": decision,
           "rule": rule_id, "note": note}
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def notify(title, text):
    try:
        subprocess.run(["osascript", "-e",
                        f'display notification "{text}" with title "{title}"'],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def prompt_user(cmd, argstr, rule):
    """真实桌面弹 allow/deny 对话框；无 GUI（本沙箱）时安全默认拒绝。"""
    try:
        script = (f'display dialog "AgentGuard 拦截到高危命令：\\n{cmd} {argstr[:60]}\\n\\n'
                  f'规则: {rule["id"]}\\n是否允许执行？" buttons {{"拒绝","允许"}} '
                  f'default button "拒绝" with title "AgentGuard 确认"')
        out = subprocess.run(["osascript", "-e", script],
                             capture_output=True, text=True, timeout=30)
        return "允许" in out.stdout
    except Exception:
        return False  # 无 UI / 超时 -> 安全默认拒绝


def exec_real(cmd, argv_rest):
    real = REAL.get(cmd)
    if real and os.path.exists(real):
        os.execv(real, [real] + argv_rest)
    else:
        os.execvpe(cmd, [cmd] + argv_rest, os.environ)


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def main():
    if len(sys.argv) < 2:
        print("usage: agentguard_check.py <guard|whitelist-add> ...", file=sys.stderr)
        sys.exit(2)

    if sys.argv[1] == "whitelist-add":
        # 预授权：agentguard_check.py whitelist-add <cmd> <args...>
        if len(sys.argv) < 3:
            print("usage: whitelist-add <cmd> <args...>", file=sys.stderr)
            sys.exit(2)
        cmd = sys.argv[2]
        argstr = " ".join(sys.argv[3:])
        ok = add_whitelist(cmd, argstr)
        print(("已加入白名单: " if ok else "白名单写入失败: ") + f"{cmd} {argstr}")
        sys.exit(0 if ok else 1)

    if sys.argv[1] != "guard":
        print("unknown subcommand", file=sys.stderr)
        sys.exit(2)

    if len(sys.argv) < 3:
        print("usage: guard <cmd> <args...>", file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[2]
    argstr = " ".join(sys.argv[3:])
    argv_rest = sys.argv[3:]
    decision, rule, whitelisted = decide(cmd, argstr)

    if decision == "allow":
        if whitelisted and rule:
            audit(cmd, argstr, "allow-whitelisted", rule["id"], "用户此前已允许")
        elif rule:
            audit(cmd, argstr, "allow", rule["id"])
        exec_real(cmd, argv_rest)
        return

    if decision == "block":
        msg = f"[AgentGuard 拦截] 规则 {rule['id']} 命中，已阻止执行：{cmd} {argstr}"
        print(msg, file=sys.stderr)
        audit(cmd, argstr, "block", rule["id"])
        notify("AgentGuard 已拦截", f"{cmd} {argstr[:50]}")
        sys.exit(1)

    if decision == "ask":
        allowed = prompt_user(cmd, argstr, rule)
        if allowed:
            add_whitelist(cmd, argstr)  # 记住本次允许，下次自动放行
            audit(cmd, argstr, "ask-allow", rule["id"], "用户允许")
            exec_real(cmd, argv_rest)
        else:
            print(f"[AgentGuard 拒绝] 用户未允许规则 {rule['id']}：{cmd} {argstr}",
                  file=sys.stderr)
            audit(cmd, argstr, "ask-deny", rule["id"])
            sys.exit(1)


if __name__ == "__main__":
    main()
