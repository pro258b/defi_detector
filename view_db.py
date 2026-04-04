#!/usr/bin/env python3
"""
View audit results from database
Usage: python view_db.py [--limit N] [--severity LEVEL]
"""

import sys
import sqlite3
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.absolute()))

from core.database_manager import DatabaseManager


def view_results(limit=None, severity=None):
    """View audit results from database"""
    db = DatabaseManager()
    db_path = db.db_path

    with sqlite3.connect(db_path) as conn:
        query = "SELECT * FROM audit_results ORDER BY created_at DESC"
        if limit:
            query += f" LIMIT {limit}"

        cursor = conn.execute(query)
        results = cursor.fetchall()

        if not results:
            print("No results found")
            return

        print(f"Found {len(results)} results:\n")

        for row in results:
            print(f"ID: {row[0]}")
            print(f"Contract: {row[2]} @ {row[1]}")
            print(f"Network: {row[3]} | Type: {row[4]}")
            print(f"Vulnerabilities: {row[5]} (Critical: {row[7]}, High: {row[6]})")
            print(f"Status: {row[12]} | Time: {row[9]:.2f}s")
            print(f"Created: {row[10]}")
            print("-" * 80)


if __name__ == "__main__":
    args = sys.argv[1:]

    limit = None
    severity = None

    i = 0
    while i < len(args):
        if args[i] == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 2
        elif args[i] == "--severity" and i + 1 < len(args):
            severity = args[i + 1]
            i += 2
        else:
            i += 1

    view_results(limit, severity)
