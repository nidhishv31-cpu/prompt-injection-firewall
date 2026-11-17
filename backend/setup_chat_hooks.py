"""Install project-local prompt hooks for Codex and Claude Code."""

import argparse
import json
import shlex
import sys
import tomllib
from pathlib import Path
from secrets import token_urlsafe
from tempfile import NamedTemporaryFile
from typing import Any
from uuid import UUID

from backend.config import ROOT
from backend.gateway.testing_scope import SCOPE_PATH, operator_path, read_scope

CONFIG_PATHS = {
    "codex": ".codex/hooks.json",
    "claude": ".claude/settings.local.json",
}
EVENT = "UserPromptSubmit"
SCRIPT = ROOT / "gateway" / "prompt_hook.py"
TOOLS = (
    "Bash|PowerShell|shell_command|exec_command|Read|LS|Write|Edit|MultiEdit|"
    "NotebookEdit|apply_patch|Glob|Grep|WebFetch|WebSearch|mcp__.*"
)
MCP_BEGIN = "# BEGIN PROMPT FIREWALL GUARDED RETRIEVAL"
MCP_END = "# END PROMPT FIREWALL GUARDED RETRIEVAL"


def hook_arguments(
    app: str, port: int, tool_guard: bool = False, test_scope: Path | None = None
) -> list[str]:
    base_python = Path(sys.base_prefix) / "python.exe"
    executable = (
        str(base_python)
        if sys.platform == "win32" and base_python.is_file()
        else sys.executable
    )
    args = [executable, "-S", str(SCRIPT), "--app", app, "--port", str(port)]
    if tool_guard:
        args.extend(("--event", "tool"))
    if test_scope is not None:
        args.extend(("--test-scope", str(test_scope)))
    return args


def hook_definition(
    app: str, port: int, tool_guard: bool = False, test_scope: Path | None = None
) -> dict[str, Any]:
    args = hook_arguments(app, port, tool_guard, test_scope)
    fields: dict[str, Any] = {
        "type": "command",
        "command": shlex.join(args),
        "timeout": 15,
    }
    if app == "codex":
        if test_scope is None:
            fields["statusMessage"] = "Checking prompt firewall"
    else:
        fields["onFailure"] = "block"
    if sys.platform == "win32":
        command = "& " + " ".join("'" + arg.replace("'", "''") + "'" for arg in args)
        if app == "codex":
            fields["commandWindows"] = command
        else:
            fields["command"] = command
            fields["shell"] = "powershell"
    return fields


def check_target(workspace: Path, target: Path) -> None:
    if not target.resolve().is_relative_to(workspace):
        raise ValueError(
            f"Hook configuration resolves outside this workspace: {target}"
        )


def merge_hook(hooks: dict[str, Any], event: str, entry: dict[str, Any]) -> bool:
    groups = hooks.setdefault(event, [])
    if not isinstance(groups, list):
        raise TypeError(f"Expected an array of {event} hooks.")
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
            raise TypeError("Expected a hook group.")
        for index, existing in enumerate(group["hooks"]):
            if not isinstance(existing, dict):
                raise TypeError("Expected a hook definition.")
            command = existing.get("command")
            if isinstance(command, str) and str(SCRIPT) in command:
                if existing == entry:
                    return False
                group["hooks"][index] = entry
                return True
    group: dict[str, Any] = {"hooks": [entry]}
    if event == "PreToolUse":
        group["matcher"] = TOOLS
    groups.append(group)
    return True


def write_config(target: Path, text: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        dir=target.parent, delete=False, mode="w", encoding="utf-8"
    ) as output:
        temporary = Path(output.name)
        output.write(text)
    try:
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def install_hook(
    workspace: Path,
    app: str,
    port: int,
    tool_guard: bool = False,
    test_scope: Path | None = None,
) -> Path:
    workspace = workspace.resolve(strict=True)
    target = workspace / CONFIG_PATHS[app]
    check_target(workspace, target)
    config = (
        json.loads(target.read_text(encoding="utf-8-sig")) if target.exists() else {}
    )
    if not isinstance(config, dict):
        raise TypeError(f"Expected a JSON object in {target}.")
    hooks = config.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise TypeError(f"Expected a hooks object in {target}.")
    changed = merge_hook(
        hooks, EVENT, hook_definition(app, port, test_scope=test_scope)
    )
    if tool_guard:
        changed |= merge_hook(
            hooks,
            "PreToolUse",
            hook_definition(app, port, tool_guard=True, test_scope=test_scope),
        )
    if changed:
        write_config(target, json.dumps(config, indent=2) + "\n")
    return target


def install_retrieval(workspace: Path, port: int) -> Path:
    workspace = workspace.resolve(strict=True)
    target = workspace / ".codex/config.toml"
    check_target(workspace, target)
    current = target.read_text(encoding="utf-8-sig") if target.exists() else ""
    if (
        current.count(MCP_BEGIN) != current.count(MCP_END)
        or current.count(MCP_BEGIN) > 1
    ):
        raise ValueError("The existing guarded retrieval configuration is incomplete.")
    if MCP_BEGIN in current:
        before, _, rest = current.partition(MCP_BEGIN)
        _, separator, after = rest.partition(MCP_END)
        if not separator:
            raise ValueError("The existing guarded retrieval configuration is invalid.")
        base = before + after.lstrip("\n")
    else:
        base = current
    servers = tomllib.loads(base).get("mcp_servers", {})
    if "firewall_notes" in servers:
        raise ValueError("The project already defines a firewall_notes MCP server.")
    section = "\n".join(
        (
            MCP_BEGIN,
            "[mcp_servers.firewall_notes]",
            f"command = {json.dumps(sys.executable)}",
            f'args = ["-m", "backend.gateway.rag_mcp", "--port", "{port}"]',
            f"cwd = {json.dumps(str(ROOT.parent))}",
            'enabled_tools = ["list_notes", "read_note"]',
            'default_tools_approval_mode = "writes"',
            MCP_END,
            "",
        )
    )
    updated = base.rstrip() + "\n\n" + section if base.strip() else section
    tomllib.loads(updated)
    if updated != current:
        write_config(target, updated)
    return target


def configure_test_scope(path: Path, session: UUID | None) -> None:
    operator = operator_path(path)
    for target in (path, operator):
        check_target(path.parent.parent.resolve(), target)
    if not operator.exists():
        write_config(operator, token_urlsafe(32) + "\n")
    scope = read_scope(path)
    if session is None:
        write_config(path, "{}\n")
    elif scope is None or scope.session != str(session):
        write_config(
            path,
            json.dumps({"session": str(session), "hook_key": token_urlsafe(32)}) + "\n",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=("all", *CONFIG_PATHS), default="all")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--protect-tools", action="store_true")
    parser.add_argument("--guarded-retrieval", action="store_true")
    parser.add_argument(
        "--test-only",
        action="store_true",
        help="Install a single-session Codex test profile.",
    )
    parser.add_argument(
        "--testing-session",
        type=UUID,
        help="Select an existing Codex session. Omit to disarm the profile.",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535.")
    if args.guarded_retrieval and args.app == "claude":
        parser.error("--guarded-retrieval installs the Codex MCP integration.")
    if args.testing_session and not args.test_only:
        parser.error("--testing-session requires --test-only.")
    if args.test_only and args.app != "all":
        parser.error("--test-only scopes both clients' project hooks. Omit --app.")
    test_scope = SCOPE_PATH if args.test_only else None
    if test_scope is not None and not test_scope.is_file():
        configure_test_scope(test_scope, None)
    for app in CONFIG_PATHS if args.app == "all" else (args.app,):
        target = install_hook(
            ROOT.parent,
            app,
            args.port,
            tool_guard=args.protect_tools or args.test_only,
            test_scope=test_scope,
        )
        print(f"{app}: {target}")
    if test_scope is not None:
        configure_test_scope(test_scope, args.testing_session)
        print(f"Testing session: {args.testing_session or 'none selected'}")
    if args.guarded_retrieval:
        print(f"Codex guarded retrieval: {install_retrieval(ROOT.parent, args.port)}")


if __name__ == "__main__":
    main()
