from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional

class NodeBase(BaseModel):
    node_id: str
    node_type: str
    risk_score: float

class NodeCreate(NodeBase):
    pass

class NodeResponse(NodeBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class RiskLogResponse(BaseModel):
    id: int
    node_id: str
    score: float
    factors: List[str]
    recorded_at: datetime
    class Config:
        from_attributes = True

class AlertResponse(BaseModel):
    id: int
    node_id: str
    severity: str
    message: str
    resolved: int
    created_at: datetime
    class Config:
        from_attributes = True