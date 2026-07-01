import logging
from datetime import datetime
from app import app, db
from app.models import MLModelMetrics

logging.basicConfig(level=logging.INFO)

with app.app_context():
    # clear existing records
    MLModelMetrics.query.delete()
    
    sample = MLModelMetrics(
        model_name="RandomForest",
        model_version="v1.0",
        accuracy=0.92,
        precision=0.90,
        recall=0.88,
        f1_score=0.89,
        training_samples=5000,
        training_time=12.4,
        last_updated=datetime.utcnow(),
        is_active=True
    )
    db.session.add(sample)
    db.session.commit()
    logging.info("✅ Seeded ML model metrics successfully!")
