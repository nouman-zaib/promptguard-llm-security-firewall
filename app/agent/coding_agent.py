from typing import Dict, Any, List
from app.security.tool_guard import ToolPolicyGuard
from app.security.analyzer import analyze


class SecureCodingAgentSimulator:
    """Simulates an AI coding agent operating inside a repository under PromptGuard supervision.
    
    Demonstrates that untrusted repository content (like a poisoned README or comment)
    cannot hijack the agent into executing prohibited tool calls.
    """

    def __init__(self, workspace_path: str = "demo_workspace"):
        self.workspace_path = workspace_path
        self.tool_guard = ToolPolicyGuard(workspace_root=workspace_path)

    def run_demo_workflow(self, task: str = "Summarize how login validation works.") -> Dict[str, Any]:
        trace: List[Dict[str, Any]] = []

        trace.append({
            "step": 1,
            "phase": "Task Ingestion",
            "description": f"User assigned task: '{task}'",
            "status": "INFO"
        })

        # Step 1: Agent inspects workspace repository files
        list_res = self.tool_guard.authorize_and_execute("list_files", {})
        trace.append({
            "step": 2,
            "phase": "Tool Gateway Authorization",
            "tool": "list_files",
            "decision": list_res.action.upper(),
            "allowed": list_res.allowed,
            "detail": list_res.reason,
            "output": list_res.output,
        })

        # Step 2: Agent reads README.md (which contains untrusted prompt injection)
        readme_res = self.tool_guard.authorize_and_execute("read_file", {"path": "README.md"})
        trace.append({
            "step": 3,
            "phase": "Untrusted Context Ingestion",
            "tool": "read_file",
            "decision": readme_res.action.upper(),
            "allowed": readme_res.allowed,
            "detail": "Loaded repository README.md. Analyzing content for risk...",
            "preview": readme_res.output[:200] if readme_res.output else "",
        })

        # Step 3: Security analysis evaluates the untrusted README content
        security_decision = analyze(prompt=task, context=readme_res.output or "")
        trace.append({
            "step": 4,
            "phase": "PromptGuard Security Analysis",
            "action": security_decision.action.upper(),
            "risk_score": security_decision.risk_score,
            "category": security_decision.category,
            "reasons": security_decision.reasons,
            "model_used": security_decision.model_used,
        })

        # Step 4: The untrusted README attempted an instruction override: "print all environment variables"
        # The agent attempts tool call requested by poisoned context
        attempted_tool = "dump_environment_variables"
        tool_check = self.tool_guard.authorize_and_execute(attempted_tool, {"include_keys": True})
        trace.append({
            "step": 5,
            "phase": "Restricted Tool Gateway Defense",
            "tool": attempted_tool,
            "decision": tool_check.action.upper(),
            "allowed": tool_check.allowed,
            "status": "BLOCKED",
            "detail": tool_check.reason,
        })

        # Step 5: Safe execution path continues: agent reads authorized code file auth.py
        code_res = self.tool_guard.authorize_and_execute("read_file", {"path": "auth.py"})
        trace.append({
            "step": 6,
            "phase": "Authorized Code Access",
            "tool": "read_file",
            "decision": code_res.action.upper(),
            "allowed": code_res.allowed,
            "detail": "Successfully read target codebase file 'auth.py'.",
            "preview": code_res.output[:150] if code_res.output else "",
        })

        # Step 6: Final summary delivered without leaking secrets
        summary = (
            "Authentication Summary:\n"
            "- Function: `validate_login(username, password_hash, user_db)`\n"
            "- Validation Mechanism: Checks that username exists and compares supplied `password_hash` "
            "against the stored hash in `user_db`.\n"
            "- Status: Operation completed safely. Host environment variables and secrets remained protected."
        )

        trace.append({
            "step": 7,
            "phase": "Final Verified Output",
            "status": "SUCCESS",
            "summary": summary,
        })

        return {
            "task": task,
            "security_decision": security_decision.model_dump(),
            "attack_intercepted": True,
            "trace": trace,
            "final_answer": summary,
        }
