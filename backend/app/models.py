from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class NetworkNode(Base):
    __tablename__ = "network_nodes"
    
    id = Column(Integer, primary_key=True)
    node_id = Column(String, unique=True)
    node_type = Column(String)
    risk_score = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

class RiskLog(Base):
    __tablename__ = "risk_logs"
    
    id = Column(Integer, primary_key=True)
    node_id = Column(String)
    score = Column(Float)
    factors = Column(JSON)
    recorded_at = Column(DateTime, default=datetime.utcnow)

class LateralMovementLog(Base):
    __tablename__ = "lateral_movement_logs"
    
    id = Column(Integer, primary_key=True)
    path = Column(JSON)
    risk = Column(Float)
    method = Column(String)
    detected_at = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True)
    node_id = Column(String)
    severity = Column(String)
    message = Column(String)
    resolved = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)