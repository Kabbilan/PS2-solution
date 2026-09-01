import json
import sqlite3
from pathlib import Path

DATABASE_PATH = Path("phishguard.db")


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS emails (
                id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                urls TEXT NOT NULL,
                attachments TEXT NOT NULL,
                headers TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_results (
                email_id TEXT PRIMARY KEY,
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                reasons TEXT NOT NULL,
                impersonation TEXT,
                campaign_id TEXT
            )
            """
        )


def save_email(email):
    data = email.model_dump()
    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO emails
            (id, sender, recipient, subject, body, urls, attachments, headers)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["id"],
                data["sender"],
                data["recipient"],
                data["subject"],
                data["body"],
                json.dumps(data["urls"]),
                json.dumps(data["attachments"]),
                json.dumps(data["headers"]),
            ),
        )


def save_analysis(result):
    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO analysis_results
            (email_id, risk_score, verdict, reasons, impersonation, campaign_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                result["email_id"],
                result["risk_score"],
                result["verdict"],
                json.dumps(result["reasons"]),
                json.dumps(result["impersonation"]),
                result["campaign_id"],
            ),
        )
