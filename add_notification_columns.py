"""
Add notification preference columns to users table
Run this script once to update the database schema
"""

import sqlite3
import os

# Path to your database
db_path = os.path.join('instance', 'ransomware_detection.db')

# Check if database exists
if not os.path.exists(db_path):
    print(f"Database not found at: {db_path}")
    print("Please check the path and try again.")
    exit(1)

print(f"Connecting to database: {db_path}")

# Connect to database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# List of columns to add
columns_to_add = [
    ('notify_threat_detection', 'BOOLEAN DEFAULT 1'),
    ('notify_scan_completion', 'BOOLEAN DEFAULT 1'),
    ('notify_security_updates', 'BOOLEAN DEFAULT 0'),
    ('notify_newsletter', 'BOOLEAN DEFAULT 0'),
    ('notify_desktop_threats', 'BOOLEAN DEFAULT 1'),
    ('notify_desktop_scan', 'BOOLEAN DEFAULT 0'),
    ('notify_desktop_system', 'BOOLEAN DEFAULT 1'),
]

print("\nAdding notification preference columns to users table...")

for column_name, column_type in columns_to_add:
    try:
        # Check if column already exists
        cursor.execute(f"PRAGMA table_info(users)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        
        if column_name in existing_columns:
            print(f"  [OK] Column '{column_name}' already exists, skipping...")
        else:
            # Add the column
            cursor.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")
            print(f"  [OK] Added column: {column_name}")
    
    except sqlite3.OperationalError as e:
        print(f"  [ERROR] Error adding column '{column_name}': {e}")

# Commit changes
conn.commit()
print("\n[SUCCESS] Database migration completed successfully!")

# Verify columns were added
cursor.execute("PRAGMA table_info(users)")
columns = cursor.fetchall()
print(f"\nTotal columns in users table: {len(columns)}")

# Show notification columns
print("\nNotification preference columns:")
for col in columns:
    if 'notify' in col[1]:
        print(f"  - {col[1]} ({col[2]})")

# Close connection
conn.close()

print("\n[DONE] You can now restart your Flask application!")
