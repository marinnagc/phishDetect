# app/models.py
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Any

class AnalyzeRequest(BaseModel):
    url: HttpUrl

class AnalyzeResult(BaseModel):
    url: str
    domain: str
    blacklisted: bool
    redirect_chain: List[str]
    whois: Optional[dict]
    ssl: Optional[dict]
    dns: Optional[dict]
    forms: Optional[list]
    levenshtein: Optional[list]
    score: int
    flags: List[str]
    raw: Optional[Any]
