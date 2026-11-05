"""
Analyzer Router for SecurePipeline.

Provides endpoints for submitting code for security analysis and
querying the supported vulnerability detection patterns.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from ..analyzer import analyze_code

router = APIRouter(prefix="/analyzer", tags=["Code Analyzer"])


# ---------------------------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------------------------

class CodeSubmission(BaseModel):
    code: str = Field(
        ..., min_length=1, max_length=50000,
        description="Source code to analyze",
    )
    language: str = Field(
        default="python",
        description="Programming language",
    )
    filename: Optional[str] = Field(
        default="submitted_code.py",
        description="Optional filename",
    )


class AnalysisFinding(BaseModel):
    id: str
    rule_id: str
    name: str
    severity: str
    cwe: str
    owasp: str
    line_number: int
    vulnerable_code: str
    explanation: str
    suggested_fix: str
    improved_code: str


class AnalysisResponse(BaseModel):
    status: str
    language: str
    filename: str
    total_vulnerabilities: int
    severity_counts: dict
    findings: list[AnalysisFinding]
    summary: str
    analysis_timestamp: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/analyze", response_model=AnalysisResponse)
def analyze_submitted_code(submission: CodeSubmission):
    """Analyze submitted code for security vulnerabilities and provide improvement suggestions."""
    try:
        result = analyze_code(
            code=submission.code,
            language=submission.language,
            filename=submission.filename,
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}",
        )


@router.get("/patterns")
def list_patterns():
    """List all supported vulnerability detection patterns."""
    from ..analyzer import VULNERABILITY_PATTERNS

    patterns_info = []
    for p in VULNERABILITY_PATTERNS:
        patterns_info.append(
            {
                "id": p["id"],
                "name": p["name"],
                "severity": p["severity"],
                "cwe": p["cwe"],
                "owasp": p["owasp"],
                "explanation": p["explanation"],
            }
        )
    return {"total_patterns": len(patterns_info), "patterns": patterns_info}
