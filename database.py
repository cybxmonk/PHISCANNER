import sqlite3
import json
import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger('phiscanner.database')

class PhishingDatabase:
    def __init__(self, db_path: str = "phishing_scanner.db"):
        """Initialize database connection and create tables if they don't exist."""
        self.db_path = db_path
        self._create_tables()
    
    def _create_tables(self) -> None:
        """Create the necessary tables if they don't exist."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create scans table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                heuristic_suspicious INTEGER NOT NULL,
                raw_results TEXT
            )
            ''')
            
            conn.commit()
            logger.info(f"Database initialized at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {str(e)}")
        finally:
            if conn:
                conn.close()
    
    def save_scan_result(self, scan_result: Dict[str, Any]) -> int:
        """Save a scan result to the database and return the row ID."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Extract main fields from scan result
            url = scan_result.get('url', '')
            timestamp = scan_result.get('timestamp', datetime.now().isoformat())
            risk_level = scan_result.get('risk_level', 'Unknown')
            heuristic_suspicious = 1 if scan_result.get('heuristic_suspicious', False) else 0
            
            # Save complete raw results as JSON
            raw_results = json.dumps(scan_result)
            
            cursor.execute('''
            INSERT INTO scans (url, timestamp, risk_level, heuristic_suspicious, raw_results)
            VALUES (?, ?, ?, ?, ?)
            ''', (url, timestamp, risk_level, heuristic_suspicious, raw_results))
            
            conn.commit()
            row_id = cursor.lastrowid
            logger.info(f"Saved scan result for {url} with ID {row_id}")
            return row_id
            
        except sqlite3.Error as e:
            logger.error(f"Error saving scan result: {str(e)}")
            if conn:
                conn.rollback()
            return -1
        finally:
            if conn:
                conn.close()
    
    def get_scan_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent scan history, limited to the specified number of entries."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Return rows as dictionaries
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, url, timestamp, risk_level, heuristic_suspicious
            FROM scans 
            ORDER BY timestamp DESC
            LIMIT ?
            ''', (limit,))
            
            results = []
            for row in cursor.fetchall():
                results.append(dict(row))
            
            return results
            
        except sqlite3.Error as e:
            logger.error(f"Error retrieving scan history: {str(e)}")
            return []
        finally:
            if conn:
                conn.close()
    
    def get_scan_details(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve detailed information for a specific scan by ID."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT raw_results FROM scans WHERE id = ?
            ''', (scan_id,))
            
            row = cursor.fetchone()
            if row and row['raw_results']:
                return json.loads(row['raw_results'])
            return None
            
        except sqlite3.Error as e:
            logger.error(f"Error retrieving scan details: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing scan details JSON: {str(e)}")
            return None
        finally:
            if conn:
                conn.close()
    
    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan result by ID."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
            conn.commit()
            
            if cursor.rowcount > 0:
                logger.info(f"Deleted scan with ID {scan_id}")
                return True
            else:
                logger.warning(f"No scan found with ID {scan_id}")
                return False
                
        except sqlite3.Error as e:
            logger.error(f"Error deleting scan: {str(e)}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                conn.close()
    
    def search_scans(self, query: str) -> List[Dict[str, Any]]:
        """Search for scan results by URL substring."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, url, timestamp, risk_level, heuristic_suspicious
            FROM scans 
            WHERE url LIKE ?
            ORDER BY timestamp DESC
            ''', (f'%{query}%',))
            
            results = []
            for row in cursor.fetchall():
                results.append(dict(row))
            
            return results
            
        except sqlite3.Error as e:
            logger.error(f"Error searching scans: {str(e)}")
            return []
        finally:
            if conn:
                conn.close() 