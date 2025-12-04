# database_migration_step3.py
"""
Database migration for STEP 3: Enhanced Audit System

Adds new columns to jtr_results table:
- strength_score (0-100)
- entropy_bits (float)
- crack_time_estimate (text)
- risk_level (CRITICAL/HIGH/MEDIUM/LOW)
- recommendations (text)
"""

import sqlite3
import sys
import os

def migrate_audit_system(db_path='pcdt.db'):
    """
    Add enhanced audit columns to jtr_results table.
    """
    print("="*70)
    print("STEP 3: DATABASE MIGRATION - Enhanced Audit System")
    print("="*70 + "\n")
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Check current schema
    print("[*] Checking jtr_results table schema...")
    c.execute("PRAGMA table_info(jtr_results)")
    columns = {row[1]: row[2] for row in c.fetchall()}
    
    print(f"[+] Current columns: {', '.join(columns.keys())}\n")
    
    # Add new columns if they don't exist
    new_columns = {
        'strength_score': 'INTEGER DEFAULT 0',
        'entropy_bits': 'REAL DEFAULT 0',
        'crack_time_estimate': 'TEXT',
        'risk_level': 'TEXT DEFAULT "UNKNOWN"',
        'recommendations': 'TEXT'
    }
    
    for col_name, col_type in new_columns.items():
        if col_name not in columns:
            print(f"[*] Adding column: {col_name}")
            try:
                c.execute(f"ALTER TABLE jtr_results ADD COLUMN {col_name} {col_type}")
                conn.commit()
                print(f"[+] Column '{col_name}' added successfully")
            except sqlite3.OperationalError as e:
                print(f"[!] Could not add column '{col_name}': {e}")
        else:
            print(f"[+] Column '{col_name}' already exists")
    
    # Verify final schema
    print("\n" + "="*70)
    print("VERIFICATION")
    print("="*70 + "\n")
    
    c.execute("PRAGMA table_info(jtr_results)")
    final_columns = [row[1] for row in c.fetchall()]
    
    print("Final jtr_results schema:")
    for i, col in enumerate(final_columns, 1):
        print(f"  {i}. {col}")
    
    # Check if all required columns exist
    required = ['strength_score', 'entropy_bits', 'crack_time_estimate', 'risk_level', 'recommendations']
    missing = [col for col in required if col not in final_columns]
    
    if missing:
        print(f"\n⚠️  Missing columns: {', '.join(missing)}")
        print("Migration incomplete!")
        conn.close()
        return False
    else:
        print("\n✅ All enhanced audit columns present!")
        print("Migration successful!")
    
    conn.close()
    
    print("\n" + "="*70)
    print("NEXT STEPS")
    print("="*70)
    print("1. Replace jtr_utils.py with enhanced version")
    print("2. Replace admin_dashboard.html with enhanced version")
    print("3. Run a new audit to see enhanced results")
    print("="*70 + "\n")
    
    return True


if __name__ == "__main__":
    # Allow custom DB path
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'pcdt.db'
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        print(f"Usage: python {sys.argv[0]} [path/to/pcdt.db]")
        sys.exit(1)
    
    success = migrate_audit_system(db_path)
    sys.exit(0 if success else 1)