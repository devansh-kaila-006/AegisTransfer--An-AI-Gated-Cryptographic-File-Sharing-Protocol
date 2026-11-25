from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
import datetime
from config import settings

engine = create_engine(
    settings.database_url, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class AuditLog(Base):
    __tablename__ = "audit"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    filename = Column(String, index=True)
    encryption_status = Column(String)
    signature_status = Column(String)
    ids_prediction = Column(String)
    ids_confidence = Column(Float)
    response_action = Column(String)
    username = Column(String)
    client_ip = Column(String)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def log_event(filename, enc_status, sig_status, ids_prediction, ids_confidence, action, username="Unknown", client_ip="Unknown"):
    db = SessionLocal()
    try:
        new_log = AuditLog(
            filename=filename,
            encryption_status=enc_status,
            signature_status=sig_status,
            ids_prediction=ids_prediction,
            ids_confidence=ids_confidence,
            response_action=action,
            username=username,
            client_ip=client_ip
        )
        db.add(new_log)
        db.commit()
    finally:
        db.close()

def get_logs():
    db = SessionLocal()
    try:
        logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(50).all()
        # Convert SQLAlchemy objects to dicts to maintain backward compatibility
        return [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "filename": log.filename,
                "encryption_status": log.encryption_status,
                "signature_status": log.signature_status,
                "ids_prediction": log.ids_prediction,
                "ids_confidence": log.ids_confidence,
                "response_action": log.response_action,
                "username": log.username,
                "client_ip": log.client_ip
            }
            for log in logs
        ]
    finally:
        db.close()
