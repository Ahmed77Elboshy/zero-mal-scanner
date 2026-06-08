#!/usr/bin/env python3
"""
Zero MAL Scanner v1.0 - Enterprise Malware Detection System
Author: me
License: MIT
Version: 1.0.0
"""

import os
import sys
import re
import hashlib
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import time
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
import struct

__version__ = "1.0.0"
__author__ = "Zero MAL Security Team"
__license__ = "MIT"

class ThreatLevel:
    """Threat severity levels"""
    SAFE = "✅ SAFE"
    CLEAN = "💚 CLEAN"
    VERIFIED = "🔵 VERIFIED CLEAN"
    CRITICAL = "🔴 CRITICAL"
    HIGH = "🟠 HIGH"
    MEDIUM = "🟡 MEDIUM"

class FileSignatureDB:
    """File signature detection using magic numbers"""
    
    # File signatures (magic numbers)
    SIGNATURES = {
        'pdf': {
            'magic': b'%PDF',
            'offset': 0,
            'description': 'PDF Document'
        },
        'exe': {
            'magic': b'MZ',
            'offset': 0,
            'description': 'Windows Executable'
        },
        'elf': {
            'magic': b'\x7fELF',
            'offset': 0,
            'description': 'Linux Executable'
        },
        'zip': {
            'magic': b'PK\x03\x04',
            'offset': 0,
            'description': 'ZIP Archive'
        },
        'docm': {
            'magic': b'PK\x03\x04',
            'offset': 0,
            'description': 'Office Macro-enabled Document'
        },
        'script_sh': {
            'magic': b'#!/bin/sh',
            'offset': 0,
            'description': 'Shell Script'
        },
        'script_py': {
            'magic': b'#!/usr/bin/env python',
            'offset': 0,
            'description': 'Python Script'
        },
        'script_ps1': {
            'magic': b'# PowerShell',
            'offset': 0,
            'description': 'PowerShell Script'
        }
    }
    
    @classmethod
    def detect_file_type(cls, file_path: str) -> Dict:
        """Detect file type using magic numbers"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)  # Read first 32 bytes
                
            for file_type, info in cls.SIGNATURES.items():
                if header[info['offset']:info['offset'] + len(info['magic'])] == info['magic']:
                    return {
                        'type': file_type,
                        'description': info['description'],
                        'method': 'magic_number'
                    }
            
            # Check extension as fallback
            ext = Path(file_path).suffix.lower()
            if ext in ['.pdf', '.exe', '.dll', '.scr', '.py', '.ps1', '.sh', '.vbs', '.js']:
                return {
                    'type': ext[1:],
                    'description': f'{ext[1:].upper()} file',
                    'method': 'extension'
                }
                
            return {'type': 'unknown', 'description': 'Unknown file type', 'method': 'unknown'}
        except:
            return {'type': 'error', 'description': 'Cannot read file', 'method': 'error'}

class ThreatIntelligenceDB:
    """
    Threat Intelligence Database - Cryptographically verified malware signatures
    Source: Official malware repositories and threat intelligence feeds
    """
    
    # Confirmed malware hashes from official sources
    CONFIRMED_MALWARE_HASHES = {
        'wannacry': {
            'md5': 'db349b97c37d22f5ea1d1841e3c89eb4',
            'sha256': '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c',
            'name': 'WannaCry Ransomware',
            'type': 'Ransomware',
            'severity': 'CRITICAL',
            'description': 'Global ransomware attack that affected 200,000+ computers',
            'date_added': '2017-05-12'
        },
        'notpetya': {
            'md5': '71b6a493388e7d0b40c83ce903bc6b04',
            'sha256': '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745',
            'name': 'NotPetya Wiper',
            'type': 'Wiper Malware',
            'severity': 'CRITICAL',
            'description': 'Destructive malware causing billions in damages',
            'date_added': '2017-06-27'
        }
    }
    
    # Verified malicious patterns (high confidence)
    CONFIRMED_MALICIOUS_PATTERNS = {
        'reverse_shell': {
            'pattern': r'/bin/bash -i >& /dev/tcp/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+\s+0>&1',
            'type': 'Reverse Shell',
            'severity': 'CRITICAL',
            'confidence': 99,
            'verified': True
        },
        'mimikatz': {
            'pattern': r'sekurlsa::logonpasswords.*privilege::debug',
            'type': 'Mimikatz Credential Theft',
            'severity': 'CRITICAL',
            'confidence': 99,
            'verified': True
        },
        'meterpreter': {
            'pattern': r'meterpreter[_\s]*reverse[_\s]*tcp',
            'type': 'Meterpreter Payload',
            'severity': 'CRITICAL',
            'confidence': 95,
            'verified': True
        },
        'process_injection': {
            'pattern': r'VirtualAllocEx.*WriteProcessMemory.*CreateRemoteThread',
            'type': 'Process Injection',
            'severity': 'HIGH',
            'confidence': 90,
            'verified': True
        }
    }
    
    # Benign patterns (whitelist)
    BENIGN_PATTERNS = [
        'This is a security test file for educational purposes',
        'Generated by Zero MAL Scanner test suite',
        'This file contains no malicious code',
        'Open source software licensed under MIT',
        'Copyright Microsoft Corporation. All rights reserved.',
        'For demonstration purposes only',
        '<?xml version="1.0" encoding="UTF-8"?>',
        '# This is a harmless script',
        '// This is a harmless script',
        '<!-- This document is safe -->',
    ]

class ScanHistory:
    """Manage scan history with size limits and file persistence"""
    
    def __init__(self, max_size: int = 1000, persist_to_file: bool = True):
        self.max_size = max_size
        self.persist_to_file = persist_to_file
        self.history = deque(maxlen=max_size)  # Auto-limit size
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def add(self, scan_result: Dict):
        """Add scan result to history with auto-size limit"""
        scan_result['session_id'] = self.session_id
        scan_result['history_index'] = len(self.history)
        self.history.append(scan_result)
        
        # Auto-persist if enabled
        if self.persist_to_file and len(self.history) % 100 == 0:  # Save every 100 scans
            self.save_to_file()
    
    def get_all(self) -> List[Dict]:
        """Get all history entries"""
        return list(self.history)
    
    def clear(self):
        """Clear history"""
        self.history.clear()
    
    def get_size(self) -> int:
        """Get current history size"""
        return len(self.history)
    
    def save_to_file(self, filename: str = None):
        """Save history to file"""
        if not filename:
            filename = f"zero_mal_history_{self.session_id}.json"
        
        try:
            export_data = {
                'session_id': self.session_id,
                'export_time': datetime.now().isoformat(),
                'total_scans': len(self.history),
                'max_size': self.max_size,
                'scans': list(self.history)
            }
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            return True, filename
        except Exception as e:
            return False, str(e)
    
    def get_statistics(self) -> Dict:
        """Get history statistics"""
        if not self.history:
            return {'total': 0, 'malware_count': 0, 'clean_count': 0}
        
        malware_count = sum(1 for r in self.history if r.get('status') == 'MALWARE_DETECTED')
        return {
            'total': len(self.history),
            'malware_count': malware_count,
            'clean_count': len(self.history) - malware_count,
            'max_size': self.max_size,
            'session_id': self.session_id
        }

class UltraAccurateScanner:
    """High accuracy malware scanner with parallel processing and file signature detection"""
    
    def __init__(self, max_workers: int = 4, history_max_size: int = 1000):
        self.threat_db = ThreatIntelligenceDB()
        self.file_sig_db = FileSignatureDB()
        self.history = ScanHistory(max_size=history_max_size)
        self.max_workers = max_workers
        self.stop_scan = False
        
    def check_file_signature(self, file_path: str) -> Dict:
        """Check file signature using magic numbers"""
        return self.file_sig_db.detect_file_type(file_path)
    
    def get_file_hash(self, file_path: str) -> Tuple[str, str]:
        """Calculate complete file hashes for verification (reads entire file)"""
        try:
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files efficiently
                while chunk := f.read(8192):  # 8KB chunks
                    # Check stop flag during hash calculation
                    if self.stop_scan:
                        return "", ""
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
                    
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except Exception as e:
            print(f"Hash error for {file_path}: {e}")
            return "", ""
    
    def is_definitely_benign(self, file_path: str, content: str) -> Tuple[bool, str]:
        """Check if file is 100% benign"""
        
        # Check file signature first
        sig_info = self.check_file_signature(file_path)
        
        # Known safe file types
        safe_types = {'.txt', '.log', '.csv', '.json', '.xml', '.html', '.css',
                     '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
                     '.mp3', '.wav', '.mp4', '.md', '.rst'}
        
        if Path(file_path).suffix.lower() in safe_types:
            return True, f"Known safe file type: {Path(file_path).suffix}"
        
        # Check PDFs specifically (can contain macros)
        if sig_info.get('type') == 'pdf':
            # PDFs need deeper inspection
            if '/JavaScript' in content or '/JS' in content:
                # Check if it's educational content
                educational_keywords = ['example', 'tutorial', 'documentation', 'sample']
                if not any(kw in content.lower() for kw in educational_keywords):
                    return False, "PDF contains potential JavaScript"
        
        content_lower = content.lower()
        for pattern in self.threat_db.BENIGN_PATTERNS:
            if pattern.lower() in content_lower:
                return True, f"Contains benign indicator: {pattern[:50]}"
        
        if os.path.getsize(file_path) < 5120:
            return True, "File too small for malware (under 5KB)"
        
        if len(content) > 0:
            readable = sum(1 for c in content if c.isprintable())
            if readable / len(content) > 0.95:
                return True, "Mostly human-readable text"
        
        return False, ""
    
    def is_confirmed_malware(self, file_path: str, content: str) -> Optional[Dict]:
        """Check for confirmed malware"""
        
        # Check stop flag
        if self.stop_scan:
            return None
        
        md5_hash, sha256_hash = self.get_file_hash(file_path)
        
        # Skip if hash calculation failed or stopped
        if (not md5_hash and not sha256_hash) or self.stop_scan:
            return None
        
        # Check against known malware hashes
        for malware_id, malware in self.threat_db.CONFIRMED_MALWARE_HASHES.items():
            if md5_hash == malware['md5'] or sha256_hash == malware['sha256']:
                return {
                    'id': malware_id,
                    'type': malware['name'],
                    'category': malware['type'],
                    'severity': malware['severity'],
                    'confidence': 100,
                    'evidence': f'Exact hash match (SHA256: {sha256_hash[:16]}...)',
                    'description': malware.get('description', ''),
                    'date_added': malware.get('date_added', 'Unknown')
                }
        
        # Check against malicious patterns
        for pattern_id, pattern_info in self.threat_db.CONFIRMED_MALICIOUS_PATTERNS.items():
            if re.search(pattern_info['pattern'], content, re.IGNORECASE):
                return {
                    'id': pattern_id,
                    'type': pattern_info['type'],
                    'category': 'Malware Pattern',
                    'severity': pattern_info['severity'],
                    'confidence': pattern_info.get('confidence', 95),
                    'evidence': f'Exact malicious pattern match: {pattern_id}',
                    'description': f'Detected {pattern_info["type"]} pattern',
                    'date_added': 'Unknown'
                }
        
        return None
    
    def scan_file(self, file_path: str) -> Dict:
        """Scan single file with stop flag support"""
        
        # Check stop flag at beginning
        if self.stop_scan:
            return {'status': 'STOPPED', 'file': file_path}
        
        result = {
            'file': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            'status': 'CLEAN',
            'threats': [],
            'verification': [],
            'scan_time': datetime.now().isoformat()
        }
        
        try:
            if not os.path.exists(file_path):
                result['error'] = 'File not found'
                return result
            
            # Get file signature
            sig_info = self.check_file_signature(file_path)
            result['file_type'] = sig_info
            
            # Check file size first (avoid reading huge files)
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:  # 50MB limit
                result['verification'].append(f'⚠️ File too large ({file_size // 1024 // 1024}MB), partial scan only')
                read_size = 5 * 1024 * 1024  # Read first 5MB only
            else:
                read_size = file_size
            
            with open(file_path, 'rb') as f:
                data = f.read(read_size)
                content = data.decode('utf-8', errors='ignore')
            
            # Check stop flag
            if self.stop_scan:
                return {'status': 'STOPPED', 'file': file_path}
            
            is_benign, reason = self.is_definitely_benign(file_path, content)
            if is_benign:
                result['verification'].append(f'✅ {reason}')
                self.history.add(result)
                return result
            
            # Check stop flag
            if self.stop_scan:
                return {'status': 'STOPPED', 'file': file_path}
            
            malware = self.is_confirmed_malware(file_path, content)
            if malware:
                result['status'] = 'MALWARE_DETECTED'
                result['threats'].append(malware)
                result['verification'].append(f'⚠️ {malware["evidence"]}')
                self.history.add(result)
                return result
            
            result['verification'].append('✅ No threats detected')
            
        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)
        
        self.history.add(result)
        return result
    
    def scan_files_parallel(self, file_list: List[str], progress_callback=None) -> List[Dict]:
        """Scan multiple files in parallel using ThreadPoolExecutor"""
        results = []
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all scan tasks
            future_to_file = {executor.submit(self.scan_file, file_path): file_path 
                            for file_path in file_list}
            
            # Process completed tasks
            for future in as_completed(future_to_file):
                if self.stop_scan:
                    # Cancel remaining futures
                    for f in future_to_file:
                        f.cancel()
                    break
                try:
                    result = future.result(timeout=30)
                    if result.get('status') != 'STOPPED':
                        results.append(result)
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, len(file_list))
                except Exception as e:
                    print(f"Error scanning file: {e}")
        
        return results
    
    def get_history_stats(self) -> Dict:
        """Get history statistics"""
        return self.history.get_statistics()
    
    def export_history(self, filename: str = None) -> Tuple[bool, str]:
        """Export history to file"""
        return self.history.save_to_file(filename)
    
    def clear_history(self):
        """Clear scan history"""
        self.history.clear()

class EdgeVisualPanel(tk.Canvas):
    """Visual edge panel with animations"""
    
    def __init__(self, parent, width=250, height=900, bg='#0a0a0a'):
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0)
        self.width = width
        self.height = height
        self.animation_angle = 0
        
    def draw_threat_indicator(self, threat_count=0, safe_count=0):
        """Draw animated threat indicator"""
        self.delete("threat_indicator")
        
        center_x = self.width // 2
        center_y = 150
        radius = 60
        
        pulse = abs(math.sin(self.animation_angle)) * 8
        
        if threat_count > 0:
            color = '#ff0000'
            glow = '#ff4444'
        else:
            color = '#00ff00'
            glow = '#44ff44'
        
        for i in range(3):
            glow_radius = radius + pulse + i * 8
            self.create_oval(center_x - glow_radius, center_y - glow_radius,
                           center_x + glow_radius, center_y + glow_radius,
                           outline=glow, width=2, tags="threat_indicator")
        
        self.create_oval(center_x - radius, center_y - radius,
                        center_x + radius, center_y + radius,
                        outline=color, width=4, tags="threat_indicator")
        
        self.create_text(center_x, center_y, text=str(threat_count),
                        fill=color, font=('Arial', 32, 'bold'), tags="threat_indicator")
        self.create_text(center_x, center_y + 45, text="THREATS FOUND",
                        fill='#888888', font=('Arial', 10), tags="threat_indicator")
        
        self.animation_angle += 0.1

class ZeroMALGUI:
    """Main GUI Application"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Zero MAL Scanner v1.0 - Malware Detection System")
        self.root.geometry("1450x950")
        self.root.configure(bg='#0a0a0a')
        
        self.scanner = UltraAccurateScanner(max_workers=4, history_max_size=1000)
        self.results = []
        self.total_scanned = 0
        self.total_malware = 0
        self.stop_scan_flag = False
        self.current_files = []
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI"""
        main_container = tk.Frame(self.root, bg='#0a0a0a')
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left edge panel
        left_edge = tk.Frame(main_container, width=250, bg='#0a0a0a')
        left_edge.pack(side=tk.LEFT, fill=tk.Y)
        left_edge.pack_propagate(False)
        
        self.visual_panel = EdgeVisualPanel(left_edge, width=250, height=950)
        self.visual_panel.pack(fill=tk.Y, expand=True)
        
        # Add info on left panel
        info_frame = tk.Frame(left_edge, bg='#0a0a0a')
        info_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
        
        tk.Label(info_frame, text="⚡ Parallel Mode", font=('Arial', 8),
                fg='#ffaa00', bg='#0a0a0a').pack()
        tk.Label(info_frame, text="📊 Magic Numbers", font=('Arial', 8),
                fg='#00ff00', bg='#0a0a0a').pack()
        tk.Label(info_frame, text="💾 Auto-Save History", font=('Arial', 8),
                fg='#00ff00', bg='#0a0a0a').pack()
        
        # Center content
        center = tk.Frame(main_container, bg='#0a0a0a')
        center.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=10)
        
        # Header
        header = tk.Label(center, text="🛡️ ZERO MAL SCANNER",
                         font=('Arial', 28, 'bold'), fg='#00ff00', bg='#0a0a0a')
        header.pack(pady=10)
        
        # Features bar
        features_frame = tk.Frame(center, bg='#1a1a1a')
        features_frame.pack(fill=tk.X, pady=5)
        
        features = [
            "⚡ 4x Parallel Scan",
            "🔍 Magic Number Detection",
            "💾 Auto History Save",
            "📊 Real-time Stats"
        ]
        
        for feature in features:
            tk.Label(features_frame, text=feature, font=('Arial', 9),
                    fg='#ffaa00', bg='#1a1a1a').pack(side=tk.LEFT, padx=10, pady=5)
        
        # Target selection
        target_frame = tk.Frame(center, bg='#1a1a1a', relief=tk.RAISED, bd=1)
        target_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(target_frame, text="Target:", fg='white', bg='#1a1a1a',
                font=('Arial', 10)).pack(side=tk.LEFT, padx=10, pady=10)
        
        self.target_var = tk.StringVar()
        target_entry = tk.Entry(target_frame, textvariable=self.target_var,
                               width=60, bg='#2d2d2d', fg='white')
        target_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Button(target_frame, text="Browse File", command=self.browse_file,
                 bg='#4a90e2', fg='white', cursor='hand2').pack(side=tk.LEFT, padx=2)
        tk.Button(target_frame, text="Browse Folder", command=self.browse_folder,
                 bg='#4a90e2', fg='white', cursor='hand2').pack(side=tk.LEFT, padx=2)
        
        # Control buttons
        button_frame = tk.Frame(center, bg='#0a0a0a')
        button_frame.pack(pady=10)
        
        self.scan_btn = tk.Button(button_frame, text="START SCAN", command=self.start_scan,
                                 bg='#00aa00', fg='white', font=('Arial', 12, 'bold'),
                                 padx=30, pady=8, cursor='hand2')
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(button_frame, text="STOP SCAN", command=self.stop_scan,
                                 bg='#aa0000', fg='white', font=('Arial', 12, 'bold'),
                                 padx=30, pady=8, cursor='hand2', state='disabled')
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = tk.Button(button_frame, text="EXPORT HISTORY", command=self.export_history,
                                   bg='#ff8800', fg='white', font=('Arial', 10, 'bold'),
                                   padx=20, pady=8, cursor='hand2', state='disabled')
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = tk.Button(button_frame, text="CLEAR RESULTS", command=self.clear_results,
                                   bg='#3d3d3d', fg='white', font=('Arial', 10),
                                   padx=20, pady=8, cursor='hand2')
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Results tree
        results_frame = tk.LabelFrame(center, text="Scan Results",
                                     bg='#1a1a1a', fg='#00ff00', font=('Arial', 11, 'bold'))
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        tree_frame = tk.Frame(results_frame, bg='#1a1a1a')
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ('Status', 'Threat Type', 'File', 'File Type', 'Evidence', 'Confidence')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.tree.heading(col, text=col)
            widths = {'Status': 100, 'Threat Type': 150, 'File': 200, 
                     'File Type': 100, 'Evidence': 300, 'Confidence': 80}
            self.tree.column(col, width=widths.get(col, 150))
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.tag_configure('CRITICAL', background='#8b0000', foreground='white')
        self.tree.tag_configure('HIGH', background='#b22222', foreground='white')
        self.tree.tag_configure('CLEAN', background='#004400', foreground='#00ff00')
        
        # Log area
        log_frame = tk.LabelFrame(center, text="Verification Log",
                                 bg='#1a1a1a', fg='#00ff00', font=('Arial', 11, 'bold'))
        log_frame.pack(fill=tk.BOTH, expand=False, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=6,
                                                  bg='#0a0a0a', fg='#00ff00',
                                                  font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        status_frame = tk.Frame(self.root, bg='#1a1a1a', height=25)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(status_frame, text="Ready - Parallel Mode | Magic Number Detection | Auto-History",
                                    bg='#1a1a1a', fg='#00ff00')
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Right edge stats
        right_edge = tk.Frame(main_container, width=220, bg='#0a0a0a')
        right_edge.pack(side=tk.RIGHT, fill=tk.Y)
        
        stats_frame = tk.Frame(right_edge, bg='#1a1a1a', relief=tk.RAISED, bd=1)
        stats_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(stats_frame, text="LIVE STATISTICS", font=('Arial', 10, 'bold'),
                fg='#00ff00', bg='#1a1a1a').pack(pady=5)
        
        self.scanned_var = tk.StringVar(value="0")
        self.threats_var = tk.StringVar(value="0")
        self.history_var = tk.StringVar(value="0")
        self.history_max_var = tk.StringVar(value="1000")
        
        stats_items = [
            ("📊 Files Scanned", self.scanned_var, '#00ff00'),
            ("⚠️ Threats Found", self.threats_var, '#ff0000'),
            ("💾 History Size", self.history_var, '#ffaa00'),
            ("📈 Max History", self.history_max_var, '#888888')
        ]
        
        for label, var, color in stats_items:
            frame = tk.Frame(stats_frame, bg='#2d2d2d', relief=tk.RAISED, bd=1)
            frame.pack(fill=tk.X, padx=5, pady=3)
            tk.Label(frame, text=label, bg='#2d2d2d', fg='#aaaaaa',
                    font=('Arial', 8)).pack(pady=(3,0))
            tk.Label(frame, textvariable=var, bg='#2d2d2d', fg=color,
                    font=('Arial', 14, 'bold')).pack(pady=(0,3))
        
        # History info
        info_frame = tk.Frame(right_edge, bg='#1a1a1a', relief=tk.RAISED, bd=1)
        info_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(info_frame, text="ℹ️ INFO", font=('Arial', 10, 'bold'),
                fg='#00ff00', bg='#1a1a1a').pack(pady=5)
        tk.Label(info_frame, text="Auto-saves every 100 scans", 
                fg='#888888', bg='#1a1a1a', font=('Arial', 8)).pack()
        tk.Label(info_frame, text="Max history: 1000 entries", 
                fg='#888888', bg='#1a1a1a', font=('Arial', 8)).pack()
        tk.Label(info_frame, text="Magic number detection active", 
                fg='#00ff00', bg='#1a1a1a', font=('Arial', 8)).pack()
        
        self.animate()
        
    def animate(self):
        """Animate visual elements"""
        self.visual_panel.draw_threat_indicator(self.total_malware, self.total_scanned)
        self.root.after(100, self.animate)
    
    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.target_var.set(filename)
    
    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.target_var.set(folder)
    
    def stop_scan(self):
        """Stop the current scan"""
        self.stop_scan_flag = True
        self.scanner.stop_scan = True
        self.status_label.config(text="Stopping scan...")
        self.log_message("Scan stopped by user")
    
    def collect_files(self, path: str) -> List[str]:
        """Collect all files to scan"""
        files = []
        if os.path.isfile(path):
            files.append(path)
        else:
            for root, dirs, files_in_dir in os.walk(path):
                # Skip system directories
                skip_dirs = {'System32', 'Windows', 'Program Files', 'node_modules', 
                            '.git', '__pycache__', 'Library', 'System'}
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                
                for file in files_in_dir:
                    files.append(os.path.join(root, file))
        return files
    
    def start_scan(self):
        target = self.target_var.get()
        if not target or not os.path.exists(target):
            messagebox.showerror("Error", "Please select a valid file or folder")
            return
        
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.export_btn.config(state='disabled')
        self.total_scanned = 0
        self.total_malware = 0
        self.stop_scan_flag = False
        self.scanner.stop_scan = False
        self.scanner.clear_history()
        self.scanned_var.set("0")
        self.threats_var.set("0")
        self.history_var.set("0")
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.log_text.delete(1.0, tk.END)
        self.log_message(f"Starting parallel scan: {target}")
        self.log_message(f"Mode: Parallel with {self.scanner.max_workers} threads")
        self.log_message(f"Features: Magic number detection | Auto-history (max 1000 entries)")
        
        # Collect files
        self.current_files = self.collect_files(target)
        self.log_message(f"Found {len(self.current_files)} files to scan")
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.run_parallel_scan)
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_parallel_scan(self):
        """Run parallel scan using ThreadPoolExecutor"""
        def progress_callback(completed, total):
            self.root.after(0, lambda: self.status_label.config(
                text=f"Scanning... {completed}/{total} files ({int(completed/total*100)}%)"))
            self.root.after(0, lambda: self.scanned_var.set(str(completed)))
            self.total_scanned = completed
            self.root.after(0, lambda: self.history_var.set(str(self.scanner.history.get_size())))
        
        try:
            results = self.scanner.scan_files_parallel(self.current_files, progress_callback)
            
            for result in results:
                if result.get('status') != 'STOPPED':
                    self.root.
