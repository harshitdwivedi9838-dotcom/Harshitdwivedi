"""
Database Module
Handles all database operations for storing network flows, anomalies, and alerts.
Uses SQLite for persistence.
"""

import sqlite3
import threading
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import json


class DatabaseManager:
    """
    Thread-safe database manager for network traffic analysis.
    Manages flows, anomalies, alerts, and statistics.
    """
    
    def __init__(self, db_path: str = "data/network_traffic.db"):
        """Initialize database connection and create tables."""
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Create a new database connection."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_database(self):
        """Create all necessary tables if they don't exist."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Flows table - stores aggregated network flows
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT NOT NULL,
                    packet_count INTEGER DEFAULT 1,
                    byte_count INTEGER DEFAULT 0,
                    duration REAL DEFAULT 0.0,
                    avg_packet_size REAL DEFAULT 0.0,
                    packets_per_second REAL DEFAULT 0.0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    flow_key TEXT NOT NULL,
                    UNIQUE(flow_key)
                )
            """)
            
            # Anomalies table - stores detected anomalies
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id INTEGER,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    anomaly_score REAL NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    details TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (flow_id) REFERENCES flows(id)
                )
            """)
            
            # Alerts table - stores rule-based alerts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    target_ip TEXT,
                    severity TEXT NOT NULL,
                    description TEXT,
                    event_count INTEGER DEFAULT 1,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Statistics table - stores aggregate statistics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_packets INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    total_flows INTEGER DEFAULT 0,
                    tcp_count INTEGER DEFAULT 0,
                    udp_count INTEGER DEFAULT 0,
                    icmp_count INTEGER DEFAULT 0,
                    anomalies_count INTEGER DEFAULT 0
                )
            """)
            
            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(first_seen)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_detected ON anomalies(detected_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_detected ON alerts(detected_at)")
            
            conn.commit()
            conn.close()
    
    def insert_flow(self, flow_data: Dict) -> int:
        """Insert or update a network flow."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            flow_key = flow_data.get('flow_key')
            
            # Try to update existing flow
            cursor.execute("""
                UPDATE flows SET
                    packet_count = packet_count + ?,
                    byte_count = byte_count + ?,
                    duration = ?,
                    avg_packet_size = ?,
                    packets_per_second = ?,
                    last_seen = CURRENT_TIMESTAMP
                WHERE flow_key = ?
            """, (
                flow_data.get('packet_count', 1),
                flow_data.get('byte_count', 0),
                flow_data.get('duration', 0.0),
                flow_data.get('avg_packet_size', 0.0),
                flow_data.get('packets_per_second', 0.0),
                flow_key
            ))
            
            if cursor.rowcount == 0:
                # Insert new flow
                cursor.execute("""
                    INSERT INTO flows (
                        src_ip, dst_ip, src_port, dst_port, protocol,
                        packet_count, byte_count, duration, avg_packet_size,
                        packets_per_second, flow_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flow_data.get('src_ip'),
                    flow_data.get('dst_ip'),
                    flow_data.get('src_port'),
                    flow_data.get('dst_port'),
                    flow_data.get('protocol'),
                    flow_data.get('packet_count', 1),
                    flow_data.get('byte_count', 0),
                    flow_data.get('duration', 0.0),
                    flow_data.get('avg_packet_size', 0.0),
                    flow_data.get('packets_per_second', 0.0),
                    flow_key
                ))
            
            flow_id = cursor.lastrowid if cursor.lastrowid else self.get_flow_id(flow_key)
            conn.commit()
            conn.close()
            return flow_id
    
    def get_flow_id(self, flow_key: str) -> Optional[int]:
        """Get flow ID by flow key."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM flows WHERE flow_key = ?", (flow_key,))
            result = cursor.fetchone()
            conn.close()
            return result['id'] if result else None
    
    def insert_anomaly(self, anomaly_data: Dict) -> int:
        """Insert an anomaly detection."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO anomalies (
                    flow_id, src_ip, dst_ip, anomaly_score,
                    anomaly_type, severity, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                anomaly_data.get('flow_id'),
                anomaly_data.get('src_ip'),
                anomaly_data.get('dst_ip'),
                anomaly_data.get('anomaly_score'),
                anomaly_data.get('anomaly_type'),
                anomaly_data.get('severity', 'medium'),
                json.dumps(anomaly_data.get('details', {}))
            ))
            
            anomaly_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return anomaly_id
    
    def insert_alert(self, alert_data: Dict) -> int:
        """Insert a rule-based alert."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO alerts (
                    alert_type, source_ip, target_ip,
                    severity, description, event_count
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                alert_data.get('alert_type'),
                alert_data.get('source_ip'),
                alert_data.get('target_ip'),
                alert_data.get('severity', 'medium'),
                alert_data.get('description'),
                alert_data.get('event_count', 1)
            ))
            
            alert_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return alert_id
    
    def get_recent_flows(self, limit: int = 100) -> List[Dict]:
        """Get recent network flows."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM flows
                ORDER BY last_seen DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
    
    def get_recent_anomalies(self, limit: int = 50) -> List[Dict]:
        """Get recent anomalies."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM anomalies
                ORDER BY detected_at DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            results = []
            for row in rows:
                data = dict(row)
                if data.get('details'):
                    try:
                        data['details'] = json.loads(data['details'])
                    except:
                        pass
                results.append(data)
            
            return results
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM alerts
                ORDER BY detected_at DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
    
    def get_suspicious_ips(self, threshold: int = 3) -> List[Dict]:
        """Get IPs with multiple anomalies/alerts."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT src_ip, COUNT(*) as count, MAX(detected_at) as last_seen
                FROM anomalies
                GROUP BY src_ip
                HAVING count >= ?
                ORDER BY count DESC
                LIMIT 50
            """, (threshold,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
    
    def get_statistics(self) -> Dict:
        """Get current traffic statistics."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            stats = {}
            
            # Total flows
            cursor.execute("SELECT COUNT(*) as count FROM flows")
            stats['total_flows'] = cursor.fetchone()['count']
            
            # Total anomalies
            cursor.execute("SELECT COUNT(*) as count FROM anomalies")
            stats['total_anomalies'] = cursor.fetchone()['count']
            
            # Total alerts
            cursor.execute("SELECT COUNT(*) as count FROM alerts")
            stats['total_alerts'] = cursor.fetchone()['count']
            
            # Recent anomalies (last hour)
            cursor.execute("""
                SELECT COUNT(*) as count FROM anomalies
                WHERE detected_at > datetime('now', '-1 hour')
            """)
            stats['recent_anomalies'] = cursor.fetchone()['count']
            
            # Protocol distribution
            cursor.execute("""
                SELECT protocol, COUNT(*) as count
                FROM flows
                GROUP BY protocol
            """)
            stats['protocol_dist'] = {row['protocol']: row['count'] for row in cursor.fetchall()}
            
            conn.close()
            return stats
    
    def get_traffic_timeline(self, hours: int = 24) -> List[Dict]:
        """Get traffic timeline for visualization."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    strftime('%Y-%m-%d %H:%M', first_seen) as time_bucket,
                    COUNT(*) as flow_count,
                    SUM(packet_count) as packet_count,
                    SUM(byte_count) as byte_count
                FROM flows
                WHERE first_seen > datetime('now', '-' || ? || ' hours')
                GROUP BY time_bucket
                ORDER BY time_bucket
            """, (hours,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
    
    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Get top IP addresses by traffic volume."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    src_ip,
                    SUM(packet_count) as total_packets,
                    SUM(byte_count) as total_bytes,
                    COUNT(*) as flow_count
                FROM flows
                GROUP BY src_ip
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
    
    def clear_old_data(self, days: int = 7):
        """Clear data older than specified days."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM flows
                WHERE first_seen < datetime('now', '-' || ? || ' days')
            """, (days,))
            
            cursor.execute("""
                DELETE FROM anomalies
                WHERE detected_at < datetime('now', '-' || ? || ' days')
            """, (days,))
            
            cursor.execute("""
                DELETE FROM alerts
                WHERE detected_at < datetime('now', '-' || ? || ' days')
            """, (days,))
            
            conn.commit()
            conn.close()
    
    def reset_database(self):
        """Clear all data from database (for testing)."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM flows")
            cursor.execute("DELETE FROM anomalies")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM statistics")
            
            conn.commit()
            conn.close()
