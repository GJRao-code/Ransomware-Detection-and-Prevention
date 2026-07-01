from app import app, db 
import logging

logging.basicConfig(level=logging.INFO)

with app.app_context():
    logging.info("Dropping all tables...")
    db.drop_all()

    logging.info("Recreating tables...")
    import models 
    db.create_all()

    logging.info("All tables recreated successfully (no emoji)")
