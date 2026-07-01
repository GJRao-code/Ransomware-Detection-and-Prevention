import logging
from app import app, db
from sqlalchemy import inspect

logging.basicConfig(level=logging.INFO)

with app.app_context():
    inspector = inspect(db.engine)
    if 'ml_model_metrics' in inspector.get_table_names():
        columns = inspector.get_columns('ml_model_metrics')
        logging.info("Schema of ml_model_metrics:")
        for col in columns:
            logging.info(f" - {col['name']} ({col['type']})")
    else:
        logging.info("Table ml_model_metrics not found!")
