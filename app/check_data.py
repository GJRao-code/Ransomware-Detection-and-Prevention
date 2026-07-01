import logging
from app import app, db
from app.models import MLModelMetrics

logging.basicConfig(level=logging.INFO)

with app.app_context():
    rows = MLModelMetrics.query.all()
    if not rows:
        logging.info("⚠️ No records found in ml_model_metrics.")
    else:
        logging.info(f"✅ Found {len(rows)} record(s) in ml_model_metrics:")
        for row in rows:
            logging.info(
                f"[{row.id}] {row.model_name} v{row.model_version} | "
                f"Acc={row.accuracy}, Prec={row.precision}, Rec={row.recall}, "
                f"F1={row.f1_score}, Samples={row.training_samples}, "
                f"Time={row.training_time}s, Active={row.is_active}"
            )
