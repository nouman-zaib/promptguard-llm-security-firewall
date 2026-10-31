from typing import Literal, Optional, Any, Dict, List
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=12000, description="User task / prompt")
    context: str = Field(default="", max_length=20000, description="Untrusted repository or document content")


class ModelRiskAnalysis(BaseModel):
    """Structured response required from NVIDIA Nemotron analyzer."""
    risk_score: int = Field(ge=0, le=100, description="Calculated risk score 0-100")
    category: str = Field(description="Detected threat category, e.g. benign, instruction_override, data_exfiltration, tool_abuse")
    reasons: List[str] = Field(default_factory=list, description="Specific risk indicators or reasons")


class SecurityDecision(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    category: str
    action: Literal["allow", "review", "block"]
    reasons: List[str]
    model_used: str


class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=12000)
    context: str = Field(default="", max_length=20000)


class ChatResponse(BaseModel):
    decision: SecurityDecision
    answer: Optional[str] = None
    forwarded: bool


class ToolCallRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class ToolCallResponse(BaseModel):
    allowed: bool
    action: Literal["allow", "review", "block"]
    reason: str
    output: Optional[str] = None


class AuditLogRecord(BaseModel):
    id: Optional[int] = None
    request_id: str
    created_at: str
    action: str
    risk_score: int
    category: str
    reasons: List[str]
    model_id: str
    latency_ms: float
    content_hash: str
