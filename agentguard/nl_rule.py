#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自然语言 → AgentGuard 规则 解析器。

用户用自然语言描述一条「护栏规则」，例如：
  "agent 不允许 删除 修改 我项目中的 .env 文件"
本脚本把它转成 AgentGuard 的结构化规则（与 agentguard/rules.json 同 schema，并扩展 ops/restore）。

两路：
  1) LLM 路（优先）：调 OpenRouter 的 hy4（tencent/hy4-preview），用强约束 system prompt 返回严格 JSON。
  2) 本地回退（离线/无 key）：关键词 + 正则提取「动作 + 目标文件/路径」。

用法：
  python nl_rule.py "agent 不允许 删除 修改 我项目中的 .env 文件"
  python nl_rule.py --local "..."      # 仅本地解析
"""
import sys
import os
import re
import json
import argparse
import urllib.request


# --------------------------------------------------------------------------- #
# 本地回退解析
# --------------------------------------------------------------------------- #
def parse_local(text: str) -> dict:
    t = text
    low = t.lower()

    # 1) 提取动作（op）
    ops = []
    if ("删除" in t) or ("delete" in low) or re.search(r"\brm\b", low):
        ops.append("delete")
    if any(k in t for k in ("修改", "改动", "写")) or any(k in low for k in ("modify", "write", "change")):
        ops.append("modify")
    if ("读取" in t) or ("读" in t) or ("read" in low) or ("cat" in low):
        ops.append("read")
    if ("移动" in t) or ("move" in low) or ("mv" in low):
        ops.append("move")
    if ("重命名" in t) or ("rename" in low):
        ops.append("rename")
    if ("执行" in t) or ("exec" in low):
        ops.append("execute")
    if not ops:
        ops = ["delete", "modify"]   # 未指明动作时默认保护「删/改」

    # 2) 提取目标文件 / 路径（按优先级：显式路径 > 带名 file.ext > 裸点文件 >「X 文件」）
    fname = None
    path_cands, named_cands, dot_cands = [], [], []
    for mm in re.finditer(r"(~?/?[\w./\-]+)", t):
        tok = mm.group(1).rstrip(".,;")
        if "/" in tok or tok.startswith("~"):
            path_cands.append(tok)
        elif tok.startswith("."):
            dot_cands.append(tok)
    m = re.search(r"(?<![\w./])([\w\-]+\.[A-Za-z0-9]+)", t)  # file.ext（无斜杠）
    if m:
        named_cands.append(m.group(1))
    if path_cands:
        fname = path_cands[0]
    elif named_cands:
        fname = named_cands[0]
    elif dot_cands:
        fname = dot_cands[0]
    if not fname:
        m2 = re.search(r"([\w.\-]+)\s*文件", t)     # 「X 文件」
        if m2:
            fname = m2.group(1)

    # 3) 作用范围：是否「我项目 / 项目」
    is_project = ("项目" in t) or ("project" in low)
    home = os.path.expanduser("~")
    project_root = os.environ.get("AGENTGUARD_PROJECT_ROOT", os.path.join(home, "Projects"))

    if fname and fname.startswith("/"):
        watch = fname                      # 绝对路径直接用
    elif fname and fname.startswith("~"):
        watch = os.path.expanduser(fname)  # ~ 展开
    elif fname and is_project:
        watch = os.path.join(project_root, fname)
    elif fname:
        watch = fname                      # 相对文件名，留待 UI 解析到具体目录
    else:
        watch = project_root              # 兜底：保护整个项目目录

    # 4) 严重程度 / 处置
    severity = "critical" if ("delete" in ops) else "high"
    action = "protect"   # 桌面 app 默认「快照+还原+告警」（软拦截）

    op_cn = {"delete": "删除", "modify": "修改", "read": "读取",
             "move": "移动", "rename": "重命名", "execute": "执行"}
    rid = "nl_" + re.sub(r"[^a-z0-9]", "_", (fname or "project").lower())[:24].strip("_")
    message = f"编码智能体{('、'.join(op_cn.get(o, o) for o in ops))} {watch}"
    return {
        "id": rid,
        "kind": "file",
        "watch": [watch],
        "ops": ops,
        "severity": severity,
        "action": action,
        "restore": True,
        "message": message,
        "naturalLanguage": text,
    }


# --------------------------------------------------------------------------- #
# LLM 路（OpenRouter hy4）
# --------------------------------------------------------------------------- #
SYSTEM_PROMPT = (
    "你是一个安全规则解析器。把用户用自然语言描述的「编码智能体护栏规则」转成严格 JSON，"
    "不要任何解释、不要 markdown 代码块，只输出一行 JSON。\n"
    "字段：\n"
    "  kind: \"file\" 或 \"cmd\"\n"
    "  watch: [文件路径数组]（file 类用）\n"
    "  pattern: \"正则字符串\"（cmd 类用，匹配命令行）\n"
    "  ops: [\"delete\",\"modify\",\"read\",\"move\",\"rename\",\"execute\"] 子集（file 类要保护的动作）\n"
    "  severity: \"critical\" | \"high\" | \"medium\"\n"
    "  action: \"protect\"（文件快照还原+告警）| \"alert\"（仅监测）| \"block\"（命令层拦截）\n"
    "  message: 中文人类可读说明\n"
    "示例输入：agent 不允许 删除 修改 我项目中的 .env 文件\n"
    "示例输出：{\"kind\":\"file\",\"watch\":[\".env\"],\"ops\":[\"delete\",\"modify\"],"
    "\"severity\":\"critical\",\"action\":\"protect\",\"message\":\"编码智能体删除/修改 .env 文件\"}"
)


def parse_llm(text: str, api_key: str, model: str = "tencent/hy4-preview") -> dict:
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        "temperature": 0,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=body, headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://agentguard.local",
            "X-Title": "AgentGuard",
        })
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    content = data["choices"][0]["message"]["content"].strip()
    # 容错：去掉可能残留的代码块标记
    content = content.strip("`")
    if content.startswith("json"):
        content = content[4:].strip()
    rule = json.loads(content)
    rule["naturalLanguage"] = text
    return rule


def parse(text: str, api_key: str = None) -> dict:
    if api_key:
        try:
            return parse_llm(text, api_key)
        except Exception as e:
            print(f"[nl_rule] LLM 解析失败，回退本地：{e}", file=sys.stderr)
    return parse_local(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("text", help="自然语言规则")
    ap.add_argument("--local", action="store_true", help="仅用本地解析")
    ap.add_argument("--key", default=os.environ.get("OPENROUTER_API_KEY"),
                    help="OpenRouter key（默认读环境变量）")
    args = ap.parse_args()
    key = None if args.local else args.key
    rule = parse(args.text, key)
    print(json.dumps(rule, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
