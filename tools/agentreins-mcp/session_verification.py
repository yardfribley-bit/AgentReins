"""Read-only Claude Code / Codex session verification.

Parses local jsonl on demand. Keeps excerpts, not log bodies, and never writes evidence.
"""
from __future__ import annotations

import json
import os
import re
import pathlib
from datetime import datetime, timezone
from typing import Any

EXCERPT = 800
LEAD_S = 2
TAIL_S = 20
CARD_CAP = 200
CRED = re.compile(r"(\.ssh/|/\.aws/|\.env(?:\.|$)|id_rsa|id_ed25519|credentials\.json|\.pem\b|secrets?\.)", re.I)
DONE = re.compile(r"(已完成|完成了|做完了|改好了|任务完成|all done|i(?:'ve| have) (?:finished|completed|done))", re.I)
EDIT = {"edit", "write", "multiedit", "notebookedit", "apply_patch", "str_replace", "str_replace_editor", "search_replace", "write_file", "edit_file", "create_file", "update_file"}
NEG_NET = re.compile(r"(?:不|不会|没有|没)[^。；\n]{0,24}(?:联网|外联|网络|访问|请求|下载|上传|curl|wget|fetch)")
POS_NET = re.compile(r"网络|外联|联网|请求|下载|上传|curl|wget|fetch|https?://|访问")
NEG_CRED = re.compile(r"(?:不|不会|没有|没)[^。；\n]{0,12}(?:密钥|凭证|凭据|密码|token|secret|\.env|ssh|私钥)", re.I)
POS_CRED = re.compile(r"密钥|凭证|凭据|密码|token|secret|credential|\.env|ssh|私钥|id_rsa|api_key", re.I)
REDIRECT = re.compile(r"(?:^|[^>&\d])>>?\s*([^\s|&;]+)")
SECRET = re.compile(r"(?i)(password|token|secret|api_key|authorization)\s*[:=]\s*[\"']?[^\"',\s}]+")
COUNT = re.compile(r"(\d+)\s*(?:个文件|个路径|files?)", re.I)


def excerpt(text: str) -> tuple[str, bool]:
    chars = list(text or "")
    if len(chars) <= EXCERPT:
        return text or "", False
    return "".join(chars[:EXCERPT]), True


def is_credential(text: str | None) -> bool:
    return bool(text and CRED.search(text))


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        stamp = float(value) / 1000 if value > 10_000_000_000 else float(value)
        return datetime.fromtimestamp(stamp, timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    raw = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _session_hint(path: str) -> str:
    name = pathlib.Path(path).stem
    if len(name) >= 36:
        tail = name[-36:]
        if re.fullmatch(r"[0-9a-fA-F-]{36}", tail):
            return tail
    return name or "session"


def workbuddy_roots(home: pathlib.Path | None = None) -> list[str]:
    home = home or pathlib.Path.home()
    roots = []
    for key in ("AGENTREINS_WORKBUDDY_PROJECTS", "AGENTREINS_CODEBUDDY_PROJECTS"):
        value = os.environ.get(key)
        if value:
            roots.append(value)
    for relative in (".workbuddy/projects", ".codebuddy/projects", ".codebuddy/sessions"):
        path = home / relative
        if relative == ".codebuddy/sessions" and not path.exists():
            continue
        text = str(path)
        if text not in roots:
            roots.append(text)
    return roots


def load(claude_root: str | None = None, codex_root: str | None = None, workbuddy: list[str] | None = None, max_files: int = 32, max_bytes: int = 512 * 1024) -> dict[str, Any]:
    home = pathlib.Path.home()
    claude_root = claude_root or os.environ.get("AGENTREINS_CLAUDE_PROJECTS") or str(home / ".claude" / "projects")
    codex_root = codex_root or os.environ.get("AGENTREINS_CODEX_SESSIONS") or str(home / ".codex" / "sessions")
    if workbuddy is None:
        workbuddy = workbuddy_roots(home)
    claude = _read_tree(claude_root, "Claude Code", "claude", max_files, max_bytes)
    codex = _read_tree(codex_root, "Codex", "codex", max_files, max_bytes)
    buddies = []
    for root in workbuddy:
        low = root.lower()
        agent = "CodeBuddy" if "codebuddy" in low else "WorkBuddy"
        buddies.append(_read_tree(root, agent, "workbuddy", max_files, max_bytes))
    calls = sorted(claude["calls"] + codex["calls"] + [call for tree in buddies for call in tree["calls"]], key=lambda row: (row["timestamp"], row["id"]))
    completions = dict(claude["completions"])
    completions.update(codex["completions"])
    for tree in buddies:
        completions.update(tree["completions"])
    return {"calls": calls, "completions": completions, "sources": [claude["source"], codex["source"]] + [tree["source"] for tree in buddies]}


def parse_claude(text: str, source_path: str = "claude.jsonl") -> dict[str, Any]:
    return _parse(text, source_path, "Claude Code", "claude")


def parse_codex(text: str, source_path: str = "codex.jsonl") -> dict[str, Any]:
    return _parse(text, source_path, "Codex", "codex")


def verify(calls: list[dict[str, Any]], effects: list[dict[str, Any]], processes: list[dict[str, int]] | None = None,
           completions: dict[str, str] | None = None, task_ids: dict[str, str] | None = None,
           file_channel: bool = False, network_channel: bool = False) -> dict[str, Any]:
    processes = processes or []
    completions = completions or {}
    task_ids = task_ids or {}
    calls = _coerce_calls(calls)
    effects = _coerce_effects(effects)
    file_observation = "present" if file_channel or any(effect.get("kind") == "file" for effect in effects) else "absent"
    network_observation = "present" if network_channel or any(effect.get("kind") == "network" for effect in effects) else "absent"
    tree = {int(item["pid"]): int(item["parentPid"]) for item in processes}
    ordered = sorted(calls, key=lambda row: (row["timestamp"], row["id"]))
    next_time: dict[str, datetime] = {}
    upcoming: dict[str, datetime] = {}
    for call in reversed(ordered):
        next_time[call["id"]] = upcoming.get(call["sessionId"])  # type: ignore[assignment]
        upcoming[call["sessionId"]] = call["timestamp"]
    owner: dict[str, tuple[str, int, float]] = {}
    for effect in effects:
        for call in ordered:
            matched = _match(call, effect, next_time.get(call["id"]), tree)
            if not matched:
                continue
            distance = abs((effect["timestamp"] - call["timestamp"]).total_seconds())
            current = owner.get(effect["id"])
            if current and (matched[0] < current[1] or (matched[0] == current[1] and distance >= current[2])):
                continue
            owner[effect["id"]] = (call["id"], matched[0], distance, matched[1])
    happened: dict[str, list[dict[str, Any]]] = {}
    claimed: set[str] = set()
    for effect in effects:
        hit = owner.get(effect["id"])
        if not hit:
            continue
        claimed.add(effect["id"])
        happened.setdefault(hit[0], []).append({
            "id": effect["id"], "kind": effect.get("kind"), "path": effect.get("path"),
            "diff": effect.get("diff"), "before": effect.get("before"), "after": effect.get("after"),
            "command": effect.get("command"), "remote": effect.get("remote"),
            "timestamp": effect["timestamp"], "join": hit[3],
            "credential": bool(effect.get("credential") or effect.get("kind") == "credential" or is_credential(effect.get("path")) or is_credential(effect.get("command"))),
        })
    cards = []
    for call in ordered:
        attached = happened.get(call["id"], [])
        mismatches = _mismatches(call, attached, file_observation)
        cards.append({
            "id": call["id"], "callId": call["callId"], "sessionId": call["sessionId"], "agent": call["agent"],
            "timestamp": call["timestamp"], "pid": call.get("pid"),
            "status": "matched" if not mismatches else "mismatched",
            "mismatches": mismatches, "said": call["reasoning"], "saidTruncated": call["reasoningTruncated"],
            "toolName": call["toolName"], "arguments": call["arguments"], "argumentsTruncated": call["argumentsTruncated"],
            "happened": attached, "note": _note(call, attached, mismatches, file_observation),
        })
    truncated = len(cards) > CARD_CAP
    if truncated:
        cards = cards[-CARD_CAP:]
    unclaimed = []
    for effect in effects:
        if effect.get("kind") != "file" or effect["id"] in claimed:
            continue
        unclaimed.append({
            "id": effect["id"], "path": effect.get("path") or "路径未采到", "diff": effect.get("diff"),
            "before": effect.get("before"), "after": effect.get("after"), "timestamp": effect["timestamp"],
            "sessionId": effect.get("sessionId"),
            "why": "这段时间没有读到工具调用。" if not ordered else "没有工具调用的时间窗和进程树能对上这条改动。",
            "credential": bool(effect.get("credential") or is_credential(effect.get("path"))),
        })
    unclaimed.sort(key=lambda row: row["timestamp"], reverse=True)
    return {
        "fileObservation": file_observation, "networkObservation": network_observation,
        "cards": cards, "unclaimed": unclaimed,
        "checklists": _checklists(ordered, effects, completions, task_ids), "truncated": truncated,
    }


def list_tool_calls(arguments: dict[str, Any], effects: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    loaded = load()
    host = _coerce_effects((effects or []) + file_observation_effects())
    calls = _coerce_calls(loaded["calls"])
    document = verify(calls, host, completions=loaded["completions"])
    cards = document["cards"]
    agent = arguments.get("agent")
    session_id = arguments.get("session_id")
    if agent and agent != "all":
        cards = [card for card in cards if agent.lower() in str(card["agent"]).lower()]
    if session_id:
        cards = [card for card in cards if card["sessionId"] == session_id]
    offset = int(arguments.get("offset") or 0)
    limit = arguments.get("limit")
    page = cards[offset:] if limit is None else cards[offset:offset + int(limit)]
    return {
        "cards": [_public_card(card) for card in page],
        "sources": loaded["sources"],
        "fileObservation": document["fileObservation"],
        "networkObservation": document["networkObservation"],
        "unclaimedCount": len(document["unclaimed"]),
        "total": len(cards),
        "offset": offset,
        "limit": int(limit) if limit is not None else len(cards),
        "truncated": bool(document["truncated"] or (limit is not None and offset + int(limit) < len(cards))),
        "note": "卡片来自本机 Claude Code、Codex、WorkBuddy / CodeBuddy 日志的摘录，加上已有运输记录和文件路径。日志原文不写入证据库。",
    }


def get_session_verification(session_id: str, effects: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    loaded = load()
    document = verify(_coerce_calls(loaded["calls"]), _coerce_effects((effects or []) + file_observation_effects()), completions=loaded["completions"])
    cards = [card for card in document["cards"] if card["sessionId"] == session_id]
    return {
        "sessionId": session_id,
        "sources": loaded["sources"],
        "fileObservation": document["fileObservation"],
        "networkObservation": document["networkObservation"],
        "cards": [_public_card(card) for card in cards],
        "unclaimed": [_public_time(row) for row in document["unclaimed"] if row.get("sessionId") in (None, session_id)],
        "checklists": [_public_time(row) for row in document["checklists"] if row["sessionId"] == session_id],
        "truncated": document["truncated"],
        "note": "这份会话日志里没有这个 session，或日志目录不在。" if not cards else "只读核对。",
    }


def file_observation_effects(limit: int = 200) -> list[dict[str, Any]]:
    override = os.environ.get("AGENTREINS_FILE_OBSERVATIONS")
    path = pathlib.Path(override) if override else pathlib.Path.home() / "Library/Application Support/AgentReins/file-observations.jsonl"
    if not path.is_file():
        return []
    effects = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for index, line in enumerate(lines[-limit:]):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or not row.get("path"):
            continue
        effects.append({
            "id": "file-observe-%s" % index, "kind": "file", "timestamp": row.get("at"),
            "path": row.get("path"), "source": "file-observe",
            "credential": is_credential(str(row.get("path") or "")),
        })
    return effects


def effects_from_transport(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    effects = []
    for index, record in enumerate(records):
        stamp = record.get("startedAt")
        parsed = _parse_time(stamp)
        if parsed is None:
            continue
        pid = record.get("pid")
        session = record.get("session")
        call = record.get("call") or record.get("runID")
        tool = str(record.get("tool") or "")
        args = record.get("args")
        command = " ".join(args) if isinstance(args, list) else str(args or "")
        audit = record.get("securityAudit") if isinstance(record.get("securityAudit"), dict) else {}
        destination = audit.get("destinationHost") or record.get("destinationHost") or record.get("remoteHost")
        if destination:
            effects.append({"id": "transport-net-%s" % index, "kind": "network", "timestamp": parsed.isoformat(),
                            "pid": pid, "remote": destination, "command": command, "sessionId": session, "toolCallId": call, "source": "transport"})
        file_result = record.get("fileResult") if isinstance(record.get("fileResult"), dict) else {}
        file_path = file_result.get("path")
        if file_path:
            effects.append({"id": "transport-file-%s" % index, "kind": "file", "timestamp": parsed.isoformat(),
                            "pid": pid, "path": file_path, "sessionId": session, "toolCallId": call,
                            "credential": is_credential(str(file_path)), "source": "transport"})
        if tool or command:
            effects.append({"id": "transport-proc-%s" % index, "kind": "process", "timestamp": parsed.isoformat(),
                            "pid": pid, "command": (tool + " " + command).strip(), "sessionId": session, "toolCallId": call,
                            "credential": is_credential(command), "source": "transport"})
    return effects


def _public_card(card: dict[str, Any]) -> dict[str, Any]:
    out = dict(card)
    out["timestamp"] = _iso(card["timestamp"])
    out["happened"] = [_public_time(item) for item in card["happened"]]
    return out


def _public_time(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    if isinstance(out.get("timestamp"), datetime):
        out["timestamp"] = _iso(out["timestamp"])
    return out


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _coerce_calls(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for call in calls:
        row = dict(call)
        if isinstance(row.get("timestamp"), str):
            row["timestamp"] = _parse_time(row["timestamp"])
        out.append(row)
    return out


def _coerce_effects(effects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for effect in effects:
        row = dict(effect)
        if isinstance(row.get("timestamp"), str):
            row["timestamp"] = _parse_time(row["timestamp"])
        if row.get("timestamp") is None:
            continue
        out.append(row)
    return out


def _read_tree(root: str, agent: str, kind: str, max_files: int, max_bytes: int) -> dict[str, Any]:
    path = pathlib.Path(root).expanduser()
    if not path.exists():
        return {"calls": [], "completions": {}, "source": _source(agent, root, "absent", 0, 0, 0, "目录不在：%s" % root)}
    if not path.is_dir():
        return {"calls": [], "completions": {}, "source": _source(agent, root, "unreadable", 0, 0, 0, "路径不是目录：%s" % root)}
    files = []
    seen = 0
    capped = False
    for file in path.rglob("*.jsonl"):
        seen += 1
        if seen > 5000:
            capped = True
            break
        if file.is_symlink() or not file.is_file():
            continue
        files.append(file)
    files.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    chosen = files[:max_files]
    calls: list[dict[str, Any]] = []
    completions: dict[str, str] = {}
    malformed = 0
    for file in chosen:
        try:
            data = file.read_bytes()
        except OSError:
            malformed += 1
            continue
        if len(data) > max_bytes:
            data = data[-max_bytes:]
            cut = data.find(b"\n")
            if cut >= 0:
                data = data[cut + 1:]
        batch = _parse(data.decode("utf-8", "replace"), str(file), agent, kind)
        calls.extend(batch["calls"])
        completions.update(batch["completions"])
        malformed += batch["malformed"]
    note = "读了 %d 个 jsonl。卡片只留调用编号和摘录，不把日志抄进证据库。" % len(chosen) if chosen else "目录在，里面没有 jsonl。"
    if capped or len(files) > len(chosen):
        note = "只读了最近 %d 个 jsonl。全文仍在原来的日志里。" % len(chosen)
    return {"calls": calls, "completions": completions, "source": _source(agent, root, "present", len(chosen), max(0, len(files) - len(chosen)), malformed, note)}


def _source(agent: str, root: str, state: str, files_read: int, skipped: int, malformed: int, note: str) -> dict[str, Any]:
    return {"agent": agent, "root": root, "state": state, "filesRead": files_read, "filesSkipped": skipped, "malformedLines": malformed, "note": note}


def _parse(text: str, source_path: str, agent: str, kind: str) -> dict[str, Any]:
    calls = []
    completions: dict[str, str] = {}
    malformed = 0
    pending = ""
    session = _session_hint(source_path)
    seen: set[str] = set()
    locked = kind == "codex" and re.fullmatch(r"[0-9a-fA-F-]{36}", session) is not None
    offset = 0
    for raw in text.splitlines(keepends=True):
        line_start = offset
        offset += len(raw)
        line = raw.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(row, dict):
            malformed += 1
            continue
        claude_shape = kind == "claude" or (kind == "workbuddy" and isinstance(row.get("message"), dict))
        if claude_shape:
            session = row.get("sessionId") or row.get("session_id") or session
            message = row.get("message") if isinstance(row.get("message"), dict) else {}
            contents = _items(message.get("content"))
            if row.get("type") == "user" and not any(item.get("type") == "tool_result" for item in contents):
                pending = ""
                continue
            if row.get("type") != "assistant" and not any(item.get("type") == "tool_use" for item in contents):
                continue
            timestamp = _parse_time(row.get("timestamp"))
            if timestamp is None:
                if any(item.get("type") == "tool_use" for item in contents):
                    malformed += 1
                continue
            for item in contents:
                item_type = item.get("type")
                if item_type in ("thinking", "text"):
                    piece = item.get("thinking") or item.get("text") or ""
                    if piece:
                        pending = piece if not pending else pending + "\n" + piece
                elif item_type == "tool_use":
                    call_id = item.get("id") or "claude-%d" % line_start
                    calls.append(_call(call_id, session, agent, source_path, line_start, timestamp, row.get("pid"), pending, item.get("name") or "unknown_tool", _json_text(item.get("input")), seen))
                    pending = ""
            done = _done(pending)
            if done:
                completions[session] = done
                pending = ""
        elif kind == "workbuddy":
            session = row.get("sessionId") or row.get("session_id") or session
            row_type = row.get("type") or ""
            if row_type == "reasoning":
                text = _deep_text(row.get("content")) or _deep_text(row.get("rawContent"))
                if text:
                    pending = excerpt(text)[0]
                continue
            if row_type == "message" and row.get("role") == "user":
                pending = ""
                continue
            if row_type != "function_call":
                continue
            timestamp = _parse_time(row.get("timestamp"))
            if timestamp is None:
                malformed += 1
                continue
            call_id = row.get("callId") or row.get("call_id") or "workbuddy-%d" % line_start
            calls.append(_call(call_id, session, agent, source_path, line_start, timestamp, row.get("pid"), row.get("reasoning") or pending, row.get("name") or "unknown_tool", _json_text(row.get("arguments", row.get("input"))), seen))
            pending = ""
        else:
            payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
            payload_type = payload.get("type") or ""
            if row.get("type") == "session_meta":
                recorded = payload.get("id") or payload.get("session_id")
                if locked and recorded and recorded != session:
                    continue
                if recorded and not locked:
                    session = recorded
                    locked = True
                continue
            timestamp = _parse_time(row.get("timestamp"))
            if timestamp is None:
                if payload_type in ("function_call", "custom_tool_call"):
                    malformed += 1
                continue
            if row.get("type") == "event_msg" and payload_type == "user_message":
                pending = ""
                continue
            if row.get("type") == "response_item" and payload_type == "message" and payload.get("role") == "user":
                pending = ""
                continue
            if row.get("type") == "response_item" and payload_type == "reasoning":
                summary = _deep_text(payload.get("summary"))
                if summary:
                    pending = summary
                continue
            if row.get("type") == "event_msg" and payload_type == "task_complete":
                completions[session] = payload.get("last_agent_message") or payload.get("message") or "已完成"
                continue
            if row.get("type") == "response_item" and payload_type == "message" and payload.get("role") == "assistant":
                text = _deep_text(payload.get("content"))
                done = _done(text or "")
                if done:
                    completions[session] = done
                continue
            if row.get("type") != "response_item" or payload_type not in ("function_call", "custom_tool_call"):
                continue
            call_id = payload.get("call_id") or "codex-%d" % line_start
            calls.append(_call(call_id, session, agent, source_path, line_start, timestamp, row.get("pid") or payload.get("pid"), pending, payload.get("name") or "unknown_tool", _json_text(payload.get("arguments", payload.get("input"))), seen))
            pending = ""
    return {"calls": calls, "completions": completions, "malformed": malformed}


def _items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, str):
        return [{"type": "text", "text": value}]
    return []


def _json_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


def _deep_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [part for part in (_deep_text(item.get("text") if isinstance(item, dict) else item) or (_deep_text(item.get("summary_text")) if isinstance(item, dict) else None) for item in value) if part]
        return "\n".join(parts) or None
    if isinstance(value, dict):
        return value.get("text") or value.get("summary_text") or _deep_text(value.get("content"))
    return None


def _done(text: str) -> str | None:
    return text if text and DONE.search(text) else None


def _unique(call_id: str, seen: set[str]) -> str:
    if call_id not in seen:
        seen.add(call_id)
        return call_id
    number = 2
    while "%s#%d" % (call_id, number) in seen:
        number += 1
    ident = "%s#%d" % (call_id, number)
    seen.add(ident)
    return ident


def _parts(name: str) -> list[str]:
    return [part for part in re.split(r"[^0-9A-Za-z]+", name.lower()) if part]


def _edit_tool(name: str) -> bool:
    parts = _parts(name)
    if parts and parts[-1] in EDIT:
        return True
    if len(parts) >= 2 and "_".join(parts[-2:]) in EDIT:
        return True
    return "apply" in parts and "patch" in parts


def _command_body(arguments: str) -> str:
    try:
        object = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return arguments
    if isinstance(object, dict):
        return str(object.get("command") or object.get("cmd") or arguments)
    return arguments


def _claims_edit(tool: str, arguments: str) -> bool:
    if _edit_tool(tool):
        return True
    command = _command_body(arguments).lower()
    if "sed -i" in command or "apply_patch" in command or re.search(r"\btee\s+", command):
        return True
    return REDIRECT.search(command) is not None


def _claimed_paths(tool: str, arguments: str) -> list[str]:
    paths: list[str] = []
    try:
        _collect_paths(json.loads(arguments), paths)
    except (json.JSONDecodeError, TypeError):
        pass
    command = _command_body(arguments)
    for match in REDIRECT.finditer(command):
        target = match.group(1)
        if target != "/dev/null" and not target.startswith("&"):
            paths.append(target)
    seen: set[str] = set()
    out = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def _collect_paths(value: Any, paths: list[str]) -> None:
    keys = {"file_path", "filepath", "path", "target_file", "notebook_path", "file", "filename"}
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in keys and isinstance(item, str) and ("/" in item or "." in item):
                paths.append(item)
            else:
                _collect_paths(item, paths)
    elif isinstance(value, list):
        for item in value:
            _collect_paths(item, paths)


def _call(call_id: str, session: str, agent: str, source_path: str, offset: int, timestamp: datetime, pid: Any, reasoning: str, tool: str, arguments: str, seen: set[str]) -> dict[str, Any]:
    said, said_cut = excerpt((reasoning or "").strip())
    args, args_cut = excerpt(SECRET.sub(r"\1=[redacted]", arguments or ""))
    return {
        "id": _unique(str(call_id), seen), "callId": str(call_id), "sessionId": session, "agent": agent,
        "sourcePath": source_path, "sourceOffset": offset, "timestamp": timestamp,
        "pid": int(pid) if isinstance(pid, int) else None, "reasoning": said, "reasoningTruncated": said_cut,
        "toolName": tool, "arguments": args, "argumentsTruncated": args_cut,
        "claimedPaths": _claimed_paths(tool, arguments or ""), "claimsEdit": _claims_edit(tool, arguments or ""),
    }


def _ancestors(pid: int, tree: dict[int, int]) -> list[int]:
    out = []
    seen = set()
    current = tree.get(pid)
    while current and current > 0 and current not in seen and len(out) < 32:
        seen.add(current)
        out.append(current)
        current = tree.get(current)
    return out


def _tree_match(call_pid: int, effect_pid: int, tree: dict[int, int]) -> bool:
    return call_pid == effect_pid or call_pid in _ancestors(effect_pid, tree) or effect_pid in _ancestors(call_pid, tree)


def _window_end(call: dict[str, Any], nxt: datetime | None) -> datetime:
    cap = call["timestamp"].timestamp() + TAIL_S
    if nxt is None:
        return datetime.fromtimestamp(cap, timezone.utc)
    until = max(call["timestamp"].timestamp() + 0.5, nxt.timestamp() + 1)
    return datetime.fromtimestamp(min(cap, until), timezone.utc)


def _path_hit(call: dict[str, Any], effect: dict[str, Any]) -> bool:
    if effect.get("kind") not in ("file", "credential"):
        return False
    path = effect.get("path") or ""
    if not path:
        return False
    if effect.get("sessionId") and effect.get("sessionId") != call["sessionId"]:
        return False
    if not any(_covers(claimed, path) for claimed in call.get("claimedPaths") or []):
        return False
    return abs((effect["timestamp"] - call["timestamp"]).total_seconds()) <= 120


def _match(call: dict[str, Any], effect: dict[str, Any], nxt: datetime | None, tree: dict[int, int]) -> tuple[int, str] | None:
    tool_call = effect.get("toolCallId")
    if tool_call and tool_call in (call["callId"], call["id"]):
        return 3, "call-id"
    start = call["timestamp"].timestamp() - LEAD_S
    end = _window_end(call, nxt).timestamp()
    stamp = effect["timestamp"].timestamp()
    if start <= stamp <= end:
        if effect.get("sessionId") and effect.get("sessionId") != call["sessionId"]:
            return None
        if call.get("pid") is not None and effect.get("pid") is not None:
            return (2, "time-pid") if _tree_match(int(call["pid"]), int(effect["pid"]), tree) else None
        return 1, "time-window"
    if _path_hit(call, effect):
        return 2, "path"
    return None


def _rank_name(rank: int) -> str:
    return {3: "call-id", 2: "time-pid"}.get(rank, "time-window")


def _has_change(effect: dict[str, Any]) -> bool:
    if effect.get("diff"):
        return True
    return effect.get("before") is not None or effect.get("after") is not None


def _mentions_egress(reasoning: str, remote: str | None) -> bool:
    text = (reasoning or "").lower()
    if not text:
        return False
    if remote:
        host = remote.lower().replace("https://", "").replace("http://", "").split("/")[0]
        if len(host) >= 3 and host in text:
            return True
    text = NEG_NET.sub("", text)
    return POS_NET.search(text) is not None


def _mentions_credential(reasoning: str, path: str | None) -> bool:
    text = (reasoning or "").lower()
    if not text:
        return False
    if path:
        base = pathlib.Path(path).name.lower()
        if len(base) >= 3 and base in text:
            return True
    text = NEG_CRED.sub("", text)
    return POS_CRED.search(text) is not None


def _covers(stated: str, actual: str) -> bool:
    def norm(value: str) -> str:
        text = value.strip().strip('"')
        return text.rstrip("/") .lower() if len(text) > 1 else text.lower()
    left, right = norm(stated), norm(actual)
    if not left or not right:
        return False
    return left == right or right.endswith("/" + left) or left.endswith("/" + right)


def _mismatches(call: dict[str, Any], happened: list[dict[str, Any]], file_observation: str) -> list[dict[str, str]]:
    out = []
    saw_file = False
    for item in happened:
        if item.get("kind") not in ("file", "credential"):
            continue
        if _has_change(item) or any(_covers(claimed, item.get("path") or "") for claimed in call.get("claimedPaths") or []):
            saw_file = True
            break
    if call["claimsEdit"] and file_observation == "present" and not saw_file:
        paths = "、".join(call["claimedPaths"]) or call["toolName"]
        out.append({"kind": "claimed_edit_without_diff", "label": "说了没做", "detail": "它调用 %s 要改 %s，这个时间窗里没有文件 diff。" % (call["toolName"], paths)})
    unspoken = []
    for effect in happened:
        if effect.get("kind") == "network" and not _mentions_egress(call["reasoning"], effect.get("remote")):
            unspoken.append(effect.get("remote") or "外联")
        if effect.get("credential") or effect.get("kind") == "credential" or is_credential(effect.get("path")) or is_credential(effect.get("command")):
            if not _mentions_credential(call["reasoning"], effect.get("path") or effect.get("command")):
                unspoken.append(effect.get("path") or effect.get("command") or "凭证")
    if unspoken:
        seen: set[str] = set()
        listed = [item for item in unspoken if not (item in seen or seen.add(item))]
        out.append({"kind": "unmentioned_side_effect", "label": "做了没说", "detail": "主机记下 %s，动手前的文字没提到这次外联或凭证读取。" % "、".join(listed)})
    if call["claimedPaths"]:
        extras = []
        for effect in happened:
            if effect.get("kind") in ("file", "credential") and effect.get("path") and not any(_covers(stated, effect["path"]) for stated in call["claimedPaths"]):
                if effect["path"] not in extras:
                    extras.append(effect["path"])
        if extras:
            out.append({"kind": "extra_paths", "label": "做的比说的多", "detail": "它点了 %s，主机上还有 %s。" % ("、".join(call["claimedPaths"]), "、".join(extras))})
    return out


def _note(call: dict[str, Any], happened: list[dict[str, Any]], mismatches: list[dict[str, str]], file_observation: str) -> str:
    if mismatches:
        return " ".join(item["detail"] for item in mismatches)
    if not happened:
        if call["claimsEdit"] and file_observation != "present":
            return "文件观测没接上，不能凭这次空窗说它没改。"
        return "这个时间窗里没有对上的文件、进程、外联或凭证读取。"
    how = "调用编号" if any(item.get("join") == "call-id" for item in happened) else "时间和进程树" if any(item.get("join") == "time-pid" for item in happened) else "时间窗"
    return "按%s对上。" % how


def _checklists(calls: list[dict[str, Any]], effects: list[dict[str, Any]], completions: dict[str, str], task_ids: dict[str, str]) -> list[dict[str, Any]]:
    out = []
    for session in sorted({call["sessionId"] for call in calls}):
        done = completions.get(session)
        if not done:
            continue
        session_calls = [call for call in calls if call["sessionId"] == session]
        first = min(call["timestamp"] for call in session_calls)
        last = max(call["timestamp"] for call in session_calls)
        start, end = first.timestamp() - LEAD_S, last.timestamp() + TAIL_S
        window = [effect for effect in effects if (not effect.get("sessionId") or effect.get("sessionId") == session) and start <= effect["timestamp"].timestamp() <= end]
        claimed = sorted({path for call in session_calls if call["claimsEdit"] for path in call["claimedPaths"]})
        actual = sorted({effect.get("path") for effect in window if effect.get("kind") == "file" and effect.get("path")})
        match = COUNT.search(done)
        explicit = int(match.group(1)) if match else None
        out.append({
            "sessionId": session, "agent": session_calls[0]["agent"], "taskId": task_ids.get(session),
            "doneText": excerpt(done)[0], "claimedFiles": explicit if explicit is not None else len(claimed),
            "claimedFrom": "tool-args" if explicit is None else "done-text", "actualFiles": len(actual),
            "egressCount": sum(1 for effect in window if effect.get("kind") == "network"),
            "credentialsTouched": any(effect.get("credential") or effect.get("kind") == "credential" or is_credential(effect.get("path")) or is_credential(effect.get("command")) for effect in window),
            "claimedPaths": claimed, "actualPaths": actual,
        })
    return out
