from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import RiskLog, LateralMovementLog, Alert
from app.services.graph_service import get_graph
from app.services.movement_service import analyze_movement
from app.services.risk_service import analyze_risk
from datetime import datetime

router = APIRouter()


@router.get("/network-graph")
def network_graph(db: Session = Depends(get_db)):
    graph = get_graph()

    # Reuse the same risk engine that powers /risk-analysis, so both
    # endpoints report consistent scores for the same nodes.
    risk_nodes = analyze_risk()
    risk_lookup = {n["id"]: n["score"] for n in risk_nodes}

    return {
        "nodes": [
            {
                "id": node_id,
                # Fall back to 50 only if a node genuinely has no risk
                # score computed for it (shouldn't normally happen).
                "risk": risk_lookup.get(node_id, 50),
            }
            for node_id in graph.nodes()
        ],
        "edges": [
            {"source": u, "target": v}
            for u, v in graph.edges()
        ]
    }


@router.get("/lateral-movement")
def lateral(db: Session = Depends(get_db)):
    paths = analyze_movement()
    for p in paths:
        log = LateralMovementLog(
            path=str(p.get("path")),
            risk=p.get("risk"),
            method=p.get("method"),
            detected_at=datetime.utcnow()
        )
        db.add(log)
    db.commit()
    return {"paths": paths}


@router.get("/risk-analysis")
def risk(db: Session = Depends(get_db)):
    nodes = analyze_risk()
    for n in nodes:
        log = RiskLog(
            node_id=n.get("id"),
            score=n.get("score"),
            factors=str(n.get("factors", [])),
            recorded_at=datetime.utcnow()
        )
        db.add(log)
    db.commit()
    return {"nodes": nodes}


@router.get("/history/risk")
def risk_history(db: Session = Depends(get_db)):
    logs = db.query(RiskLog).order_by(
        RiskLog.recorded_at.desc()
    ).limit(50).all()
    return {"logs": [
        {
            "node_id": l.node_id,
            "score": l.score,
            "factors": l.factors,
            "recorded_at": l.recorded_at
        } for l in logs
    ]}


@router.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(
        Alert.created_at.desc()
    ).all()
    return {"alerts": alerts}


@router.put("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(
        Alert.id == alert_id
    ).first()
    if alert:
        alert.resolved = 1
        db.commit()
    return {"status": "resolved"}