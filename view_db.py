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

    query = "SELECT * FROM audit_results WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())

    query += " ORDER BY timestamp DESC"

    if limit:
        query += f" LIMIT {limit}"

    cursor = db.conn.execute(query, params)
    results = cursor.fetchall()

    if not results:
        print("No results found")
        return

    print(f"Found {len(results)} results:\n")

    for row in results:
        print(f"ID: {row[0]}")
        print(f"Contract: {row[1]}")
        print(f"Severity: {row[2]}")
        print(f"Title: {row[3]}")
        print(f"Description: {row[4][:200]}..." if len(row[4]) > 200 else f"Description: {row[4]}")
        print(f"Timestamp: {row[5]}")
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
