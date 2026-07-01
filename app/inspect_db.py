from app import app, db
import logging

logging.basicConfig(level=logging.INFO)

with app.app_context():
    import models  # <-- add this
    db.create_all()  # ensure tables exist

    inspector = db.inspect(db.engine)
    tables = inspector.get_table_names()
    logging.info(f"Tables in ransomware_detection.db: {tables}")
