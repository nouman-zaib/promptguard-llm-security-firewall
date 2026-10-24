from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List

from app.schemas import (
    AnalyzeRequest,
    SecurityDecision,
    ChatRequest,
    ChatResponse,
    ToolCallRequest,
    ToolCallResponse,
)
from app.security.analyzer import analyze
from app.security.tool_guard import ToolPolicyGuard
from app.router.llm_router import secure_chat
from app.storage.audit import get_recent_audit_events, get_audit_summary
from app.agent.coding_agent import SecureCodingAgentSimulator

app = FastAPI(
    title="PromptGuard API",
    description="Risk-Aware Security Gateway for AI Coding Agents and LLM Routers",
    version="0.1.0",
)

# Enable CORS for Streamlit and external frontend integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

tool_guard = ToolPolicyGuard(workspace_root="demo_workspace")
agent_simulator = SecureCodingAgentSimulator(workspace_path="demo_workspace")


@app.get("/health")
def health() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/api/analyze", response_model=SecurityDecision)
def analyze_route(request: AnalyzeRequest):
    """Analyzes a user prompt and untrusted external context, enforcing security policy.
    
    Fails closed if the analysis pipeline is unavailable or malformed.
    """
    try:
        decision = analyze(request.prompt, request.context)
        return decision
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Security analysis unavailable; request not forwarded. ({str(e)})",
        )


@app.post("/api/chat", response_model=ChatResponse)
def chat_route(request: ChatRequest):
    """Secure chat route: prompt is routed to the task LLM ONLY if policy decision is ALLOW."""
    try:
        result = secure_chat(request.prompt, request.context)
        return ChatResponse(
            decision=SecurityDecision(**result["decision"]),
            answer=result["answer"],
            forwarded=result["forwarded"],
        )
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Router unavailable or security policy failure: {str(e)}",
        )


@app.post("/api/tools/execute", response_model=ToolCallResponse)
def execute_tool_route(request: ToolCallRequest):
    """Restricted tool gateway: authorizes and executes tools strictly inside workspace bounds."""
    try:
        response = tool_guard.authorize_and_execute(request.tool_name, request.arguments)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Tool authorization error: {str(e)}",
        )


@app.get("/api/audit")
def audit_events_route(limit: int = Query(default=50, ge=1, le=500)) -> List[Dict[str, Any]]:
    """Returns recent audit events with sensitive text redacted."""
    return get_recent_audit_events(limit=limit)


@app.get("/api/audit/summary")
def audit_summary_route() -> Dict[str, Any]:
    """Returns aggregated audit metrics."""
    return get_audit_summary()


@app.post("/api/agent/demo")
def agent_demo_route(task: str = "Summarize how login validation works.") -> Dict[str, Any]:
    """Simulates a coding agent workflow confronted with an indirect prompt injection in a repository README."""
    try:
        return agent_simulator.run_demo_workflow(task=task)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Agent simulation failed: {str(e)}",
        )
