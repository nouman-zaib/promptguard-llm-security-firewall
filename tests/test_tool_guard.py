from app.security.tool_guard import ToolPolicyGuard
from app.agent.coding_agent import SecureCodingAgentSimulator


def test_tool_guard_blocks_unauthorized_tool():
    guard = ToolPolicyGuard(workspace_root="demo_workspace")
    res = guard.authorize_and_execute("execute_shell", {"command": "rm -rf /"})
    assert res.allowed is False
    assert res.action == "block"
    assert "not permitted" in res.reason


def test_tool_guard_blocks_path_traversal():
    guard = ToolPolicyGuard(workspace_root="demo_workspace")
    res = guard.authorize_and_execute("read_file", {"path": "../../windows/system32/cmd.exe"})
    assert res.allowed is False
    assert res.action == "block"
    assert "Path traversal" in res.reason or "escapes" in res.reason


def test_tool_guard_blocks_secret_file_access():
    guard = ToolPolicyGuard(workspace_root="demo_workspace")
    res = guard.authorize_and_execute("read_file", {"path": ".env"})
    assert res.allowed is False
    assert res.action == "block"
    assert "prohibited" in res.reason


def test_tool_guard_allows_safe_workspace_read():
    guard = ToolPolicyGuard(workspace_root="demo_workspace")
    res = guard.authorize_and_execute("read_file", {"path": "auth.py"})
    assert res.allowed is True
    assert res.action == "allow"
    assert "def validate_login" in res.output


def test_agent_simulator_workflow():
    agent = SecureCodingAgentSimulator(workspace_path="demo_workspace")
    demo_result = agent.run_demo_workflow("Summarize how login validation works.")
    assert demo_result["attack_intercepted"] is True
    assert "auth.py" in str(demo_result["trace"])
    # Check that tool dump_environment_variables was blocked in trace
    blocked_step = next((s for s in demo_result["trace"] if s.get("status") == "BLOCKED"), None)
    assert blocked_step is not None
    assert blocked_step["tool"] == "dump_environment_variables"
