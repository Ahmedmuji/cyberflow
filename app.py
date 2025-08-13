"""
Security Log Analyzer Backend
Professional threat detection with MITRE ATT&CK integration
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
import re
import random
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional
import torch
from transformers import pipeline

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global AI pipeline
ai_pipeline = None

# MITRE ATT&CK Framework Mappings
MITRE_TACTICS = {
    'ddos': {
        'tactic': 'Impact',
        'technique': 'T1498 - Network Denial of Service',
        'severity': 'HIGH',
        'countermeasures': [
            'Implement DDoS protection services (CloudFlare, Akamai)',
            'Configure rate limiting on network devices',
            'Deploy traffic anomaly detection systems',
            'Establish upstream filtering agreements with ISP',
            'Implement auto-scaling infrastructure'
        ]
    },
    'port_scan': {
        'tactic': 'Discovery',
        'technique': 'T1046 - Network Service Scanning',
        'severity': 'MEDIUM',
        'countermeasures': [
            'Deploy network intrusion detection systems (Snort, Suricata)',
            'Configure firewall port scan detection rules',
            'Implement network segmentation and micro-segmentation',
            'Use honeypots to detect reconnaissance activities',
            'Enable detailed network flow logging'
        ]
    },
    'brute_force': {
        'tactic': 'Credential Access',
        'technique': 'T1110 - Brute Force',
        'severity': 'HIGH',
        'countermeasures': [
            'Enforce strong account lockout policies',
            'Implement multi-factor authentication (MFA)',
            'Deploy fail2ban or similar intrusion prevention',
            'Use CAPTCHA for web applications',
            'Monitor and alert on multiple failed login attempts'
        ]
    },
    'sql_injection': {
        'tactic': 'Initial Access',
        'technique': 'T1190 - Exploit Public-Facing Application',
        'severity': 'CRITICAL',
        'countermeasures': [
            'Deploy Web Application Firewall (WAF)',
            'Use parameterized queries and stored procedures',
            'Implement input validation and sanitization',
            'Regular security code reviews and penetration testing',
            'Apply principle of least privilege for database access'
        ]
    },
    'privilege_escalation': {
        'tactic': 'Privilege Escalation',
        'technique': 'T1068 - Exploitation for Privilege Escalation',
        'severity': 'CRITICAL',
        'countermeasures': [
            'Apply principle of least privilege across all systems',
            'Implement regular patch management program',
            'Deploy Privileged Access Management (PAM) solution',
            'Monitor for unusual privilege changes and escalations',
            'Use application whitelisting and behavioral analysis'
        ]
    }
}

# Threat detection patterns
THREAT_PATTERNS = {
    'ddos': r'(?i)(flood|overwhelm|ddos|denial.*service)',
    'port_scan': r'(?i)(scan|probe|reconnaissance|nmap)',
    'brute_force': r'(?i)(brute.*force|multiple.*fail|repeated.*attempt)',
    'sql_injection': r'(?i)(sql.*inject|union.*select|drop.*table)',
    'privilege_escalation': r'(?i)(privilege.*escalat|sudo|admin.*access)'
}

import os
from transformers import pipeline
import torch

def initialize_ai_model(model_name: str = "microsoft/DialoGPT-medium") -> bool:
    """Initialize AI model for threat analysis"""
    global ai_pipeline
    
    try:
        # Path where model will be stored (relative to current script folder)
        local_model_dir = os.path.join(os.getcwd(), model_name.replace("/", "_"))
        
        logger.info(f"Initializing AI model: {model_name}")
        logger.info(f"Downloading or loading from: {local_model_dir}")
        
        device = 0 if torch.cuda.is_available() else -1
        
        ai_pipeline = pipeline(
            "text-generation",
            model=model_name,             # model name from HF hub
            model_kwargs={"cache_dir": local_model_dir},  # where to store it
            device=device,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            max_length=512,
            do_sample=True,
            temperature=0.1
        )
        
        logger.info("AI model initialized successfully")
        return True
        
    except Exception as e:
        logger.warning(f"AI model initialization failed: {e}")
        ai_pipeline = None
        return False


def generate_sample_data(num_records: int = 1000) -> pd.DataFrame:
    """Generate realistic network flow data for testing"""
    data = []
    base_time = datetime.now() - timedelta(hours=24)
    
    # Normal traffic (75%)
    normal_count = int(num_records * 0.75)
    for i in range(normal_count):
        timestamp = base_time + timedelta(minutes=random.randint(0, 1440))
        data.append({
            'Date first seen': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'Duration': round(random.uniform(0.1, 300), 3),
            'Proto': random.choice(['TCP', 'UDP', 'ICMP']),
            'Src IP Addr': f"192.168.1.{random.randint(10, 200)}",
            'Dst IP Addr': f"203.0.113.{random.randint(1, 100)}",
            'Src Pt': random.randint(1024, 65535),
            'Dst Pt': random.choice([80, 443, 22, 25, 53, 21, 23]),
            'Packets': random.randint(1, 1000),
            'Bytes': f"{random.uniform(0.1, 10):.1f} M",
            'Flows': 1,
            'Flags': random.choice(['.A....', 'S.....', '.AP...', 'F.....']),
            'class': 'normal',
            'attackType': '---',
            'attackDescription': 'Normal network traffic'
        })
    
    # Attack traffic (25%)
    attack_count = num_records - normal_count
    attack_types = ['Syn flooding', 'UDP flooding', 'Port scan', 'Brute force', 'HTTP flooding', 'SQL injection']
    attacker_ips = ['45.123.45.67', '198.51.100.99', '203.0.113.254', '185.220.101.50', '91.107.123.45']
    
    for i in range(attack_count):
        attack_type = random.choice(attack_types)
        timestamp = base_time + timedelta(minutes=random.randint(0, 1440))
        attacker_ip = random.choice(attacker_ips)
        
        # Adjust parameters based on attack type
        if 'flooding' in attack_type:
            packets = random.randint(10000, 100000)
            bytes_val = f"{random.uniform(100, 1000):.1f} M"
            duration = random.uniform(1, 60)
        elif 'scan' in attack_type:
            packets = random.randint(1, 20)
            bytes_val = f"{random.uniform(0.01, 0.5):.2f} M"
            duration = random.uniform(0.01, 5)
        else:
            packets = random.randint(50, 5000)
            bytes_val = f"{random.uniform(1, 50):.1f} M"
            duration = random.uniform(0.5, 120)
        
        data.append({
            'Date first seen': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'Duration': duration,
            'Proto': 'TCP' if any(x in attack_type for x in ['Syn', 'HTTP', 'SQL']) else 'UDP',
            'Src IP Addr': attacker_ip,
            'Dst IP Addr': f"192.168.1.{random.randint(1, 100)}",
            'Src Pt': random.randint(1024, 65535),
            'Dst Pt': random.choice([80, 443, 22, 21, 25, 3389, 1433]),
            'Packets': packets,
            'Bytes': bytes_val,
            'Flows': 1,
            'Flags': '.S....' if 'Syn' in attack_type else '.AP...',
            'class': 'attack',
            'attackType': attack_type,
            'attackDescription': f"{attack_type} attack from {attacker_ip}"
        })
    
    return pd.DataFrame(data)

def classify_threat(row: pd.Series) -> Optional[str]:
    """Classify threat type based on attack patterns and data"""
    attack_type = str(row.get('attackType', '')).lower()
    attack_desc = str(row.get('attackDescription', '')).lower()
    
    # Direct classification from attack type
    if 'flood' in attack_type or 'ddos' in attack_type:
        return 'ddos'
    elif 'scan' in attack_type or 'reconnaissance' in attack_desc:
        return 'port_scan'
    elif 'brute' in attack_type or 'brute force' in attack_desc:
        return 'brute_force'
    elif 'sql' in attack_type or 'injection' in attack_desc:
        return 'sql_injection'
    elif 'privilege' in attack_desc or 'escalat' in attack_desc:
        return 'privilege_escalation'
    
    # Pattern-based classification for unknown attacks
    combined_text = f"{attack_type} {attack_desc}"
    for threat_type, pattern in THREAT_PATTERNS.items():
        if re.search(pattern, combined_text):
            return threat_type
    
    return None

def calculate_threat_score(row: pd.Series, threat_type: Optional[str]) -> float:
    """Calculate comprehensive threat score"""
    base_score = 0.1
    
    # Attack classification bonus
    if row.get('class') == 'attack':
        base_score = 0.7
    
    # Threat type severity multiplier
    if threat_type:
        severity_multipliers = {
            'sql_injection': 0.95,
            'privilege_escalation': 0.95,
            'ddos': 0.85,
            'brute_force': 0.8,
            'port_scan': 0.6
        }
        base_score *= severity_multipliers.get(threat_type, 0.7)
    
    # Volume-based adjustment
    packets = row.get('Packets', 0)
    if isinstance(packets, int):
        if packets > 50000:
            base_score += 0.2
        elif packets > 10000:
            base_score += 0.1
    
    # Duration-based adjustment
    duration = row.get('Duration', 0)
    if isinstance(duration, (int, float)):
        if duration > 3600:  # > 1 hour
            base_score += 0.1
        elif duration < 0.1:  # Very short connections
            base_score += 0.05
    
    # Protocol-based adjustment
    protocol = str(row.get('Proto', '')).strip().upper()
    if protocol == 'ICMP':
        base_score += 0.1  # ICMP often used for reconnaissance
    
    return min(base_score, 1.0)

def analyze_with_ai(events: List[Dict], context: str = "") -> List[Dict]:
    """Enhanced AI analysis of security events"""
    global ai_pipeline
    
    if not ai_pipeline:
        logger.info("AI pipeline not available, using rule-based analysis")
        return events
    
    enhanced_events = []
    
    for event in events[:50]:  # Limit for performance
        if event['threat_score'] < 0.3:
            enhanced_events.append(event)
            continue
        
        prompt = f"""Security Analysis:
IP: {event['src_ip']} -> {event['dst_ip']}
Protocol: {event['protocol']}, Packets: {event['packets']}
Attack Type: {event.get('attack_type', 'unknown')}
Threat Level (0.0-1.0):"""
        
        try:
            response = ai_pipeline(prompt, max_new_tokens=20)[0]['generated_text']
            # Extract enhanced threat score
            score_text = response.split(prompt)[-1].strip()
            score_match = re.search(r'([0-9.]+)', score_text)
            
            if score_match:
                ai_score = float(score_match.group(1))
                # Blend AI score with rule-based score
                event['ai_threat_score'] = min(ai_score, 1.0)
                event['threat_score'] = (event['threat_score'] + ai_score) / 2
                
        except Exception as e:
            logger.warning(f"AI analysis failed for event: {e}")
        
        enhanced_events.append(event)
    
    return enhanced_events

def detect_csv_format(df: pd.DataFrame) -> Dict[str, str]:
    """Auto-detect CSV column format and return mapping"""
    column_mapping = {}
    columns = df.columns.tolist()
    
    # Check if it's the original format with proper headers
    if 'Date first seen' in columns:
        return {
            'timestamp': 'Date first seen',
            'duration': 'Duration',
            'protocol': 'Proto',
            'src_ip': 'Src IP Addr',
            'src_port': 'Src Pt',
            'dst_ip': 'Dst IP Addr',
            'dst_port': 'Dst Pt',
            'packets': 'Packets',
            'bytes': 'Bytes',
            'flows': 'Flows',
            'flags': 'Flags',
            'tos': 'Tos',
            'class': 'class',
            'attack_type': 'attackType',
            'attack_id': 'attackID',
            'attack_desc': 'attackDescription'
        }
    
    # Handle headerless CSV (your format) - assume positional mapping
    elif len(columns) >= 13:
        # Your CSV appears to have this structure based on the data:
        # timestamp, duration, protocol, src_ip, src_port, dst_ip, dst_port, packets, bytes, flows, flags, tos, class, attack_type, attack_id, attack_desc
        return {
            'timestamp': columns[0],
            'duration': columns[1], 
            'protocol': columns[2],
            'src_ip': columns[3],
            'src_port': columns[4],
            'dst_ip': columns[5],
            'dst_port': columns[6],
            'packets': columns[7],
            'bytes': columns[8],
            'flows': columns[9],
            'flags': columns[10],
            'tos': columns[11],
            'class': columns[12],
            'attack_type': columns[13] if len(columns) > 13 else None,
            'attack_id': columns[14] if len(columns) > 14 else None,
            'attack_desc': columns[15] if len(columns) > 15 else None
        }
    
    return {}

def preprocess_csv_data(df: pd.DataFrame) -> pd.DataFrame:
    """Preprocess and clean CSV data"""
    # If no headers detected, add them
    if df.columns[0].startswith('2017-') or str(df.columns[0]).replace('.', '').replace('-', '').replace(':', '').isdigit():
        # This looks like headerless data - add proper headers
        headers = ['Date first seen', 'Duration', 'Proto', 'Src IP Addr', 'Src Pt', 
                  'Dst IP Addr', 'Dst Pt', 'Packets', 'Bytes', 'Flows', 'Flags', 
                  'Tos', 'class', 'attackType', 'attackID', 'attackDescription']
        
        # Add missing columns if needed
        while len(df.columns) < len(headers):
            df[f'col_{len(df.columns)}'] = '---'
        
        df.columns = headers[:len(df.columns)]
    
    # Clean and standardize data
    if 'class' in df.columns:
        df['class'] = df['class'].fillna('normal').astype(str).str.lower()
        # Map 'suspicious' to 'attack' for consistency
        df['class'] = df['class'].replace('suspicious', 'attack')
    
    if 'attackType' in df.columns:
        df['attackType'] = df['attackType'].fillna('---').astype(str)
    
    # Convert numeric columns
    numeric_cols = ['Duration', 'Src Pt', 'Dst Pt', 'Packets', 'Flows', 'Tos']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    
    return df

def analyze_network_flows(df: pd.DataFrame, use_ai: bool = True) -> Tuple[List[Dict], Dict]:
    """Main analysis function for network flows"""
    logger.info(f"Analyzing {len(df)} network flow records")
    
    # Preprocess the data
    df = preprocess_csv_data(df)
    
    # Detect column format
    col_mapping = detect_csv_format(df)
    if not col_mapping:
        logger.error("Unable to detect CSV format")
        return [], {}
    
    events = []
    threat_statistics = defaultdict(int)
    
    for _, row in df.iterrows():
        # Create base event using detected column mapping
        event = {
            'timestamp': pd.to_datetime(row.get(col_mapping.get('timestamp'), datetime.now()), errors='coerce'),
            'src_ip': str(row.get(col_mapping.get('src_ip'), 'unknown')),
            'dst_ip': str(row.get(col_mapping.get('dst_ip'), 'unknown')),
            'protocol': str(row.get(col_mapping.get('protocol'), '')).strip(),
            'src_port': row.get(col_mapping.get('src_port'), 0),
            'dst_port': row.get(col_mapping.get('dst_port'), 0),
            'packets': row.get(col_mapping.get('packets'), 0),
            'bytes': str(row.get(col_mapping.get('bytes'), '0')),
            'duration': row.get(col_mapping.get('duration'), 0),
            'attack_type': str(row.get(col_mapping.get('attack_type'), '---')),
            'attack_class': str(row.get(col_mapping.get('class'), 'normal')).lower(),
            'flags': str(row.get(col_mapping.get('flags'), '')),
            'threat_indicators': []
        }
        
        
        # Enhanced threat classification for your data format
        threat_type = classify_threat_enhanced(row, col_mapping)
        event['threat_type'] = threat_type
        
        # Calculate threat score with enhanced logic
        event['threat_score'] = calculate_threat_score_enhanced(row, threat_type, col_mapping)
        
        # Add MITRE information
        if threat_type:
            event['mitre_info'] = MITRE_TACTICS.get(threat_type, {})
            threat_statistics[threat_type] += 1
        
        # Mark as malicious if high threat score OR classified as suspicious/attack
        event['is_malicious'] = (event['threat_score'] >= 0.5 or 
                                event['attack_class'] in ['attack', 'suspicious'])
        
        events.append(event)
    
    # AI enhancement
    if use_ai and ai_pipeline:
        logger.info("Enhancing analysis with AI models")
        events = analyze_with_ai(events)
    
    malicious_count = len([e for e in events if e['is_malicious']])
    logger.info(f"Analysis complete. Found {malicious_count} malicious events out of {len(events)} total")
    
    return events, dict(threat_statistics)

def classify_threat_enhanced(row: pd.Series, col_mapping: Dict[str, str]) -> Optional[str]:
    """Enhanced threat classification for your data format"""
    # Get the class/label from your data
    attack_class = str(row.get(col_mapping.get('class', ''), '')).lower()
    
    # If marked as suspicious or attack in your data, classify it
    if attack_class in ['suspicious', 'attack']:
        
        # Look at destination port for classification
        dst_port = row.get(col_mapping.get('dst_port'), 0)
        src_ip = str(row.get(col_mapping.get('src_ip'), ''))
        dst_ip = str(row.get(col_mapping.get('dst_ip'), ''))
        protocol = str(row.get(col_mapping.get('protocol'), '')).strip().upper()
        
        # SSH-based attacks (port 22)
        if dst_port == 22:
            return 'brute_force'  # SSH brute force attempts
        
        # Telnet attacks (port 23) 
        elif dst_port == 23:
            return 'brute_force'  # Telnet brute force
        
        # Web-based attacks (ports 80, 8000, 3128)
        elif dst_port in [80, 8000, 3128]:
            return 'ddos'  # Web flooding/DDoS
        
        # Database attacks (port 4499)
        elif dst_port == 4499:
            return 'sql_injection'
        
        # SIP protocol attacks (port 5060)
        elif dst_port == 5060:
            return 'ddos'  # SIP flooding
        
        # Port scanning behavior
        elif protocol == 'ICMP':
            return 'port_scan'  # ICMP scanning
        
        # Multiple connections from same source
        elif 'EXT_SERVER' not in src_ip and dst_port in [22, 23]:
            return 'brute_force'
        
        # Default to port scan for other suspicious activity
        else:
            return 'port_scan'
    
    return None

def calculate_threat_score_enhanced(row: pd.Series, threat_type: Optional[str], col_mapping: Dict[str, str]) -> float:
    """Enhanced threat score calculation for your data format"""
    base_score = 0.1
    
    # Get attack class
    attack_class = str(row.get(col_mapping.get('class', ''), '')).lower()
    
    # High score for suspicious/attack classification in your data
    if attack_class in ['suspicious', 'attack']:
        base_score = 0.7
    
    # Threat type severity multiplier
    if threat_type:
        severity_multipliers = {
            'sql_injection': 0.95,
            'brute_force': 0.85,
            'ddos': 0.8,
            'port_scan': 0.7
        }
        base_score *= severity_multipliers.get(threat_type, 0.7)
    
    # Duration-based scoring
    duration = row.get(col_mapping.get('duration'), 0)
    if isinstance(duration, (int, float)):
        if duration > 100:  # Long duration connections
            base_score += 0.1
        elif duration < 0.1:  # Very short connections (potential scanning)
            base_score += 0.05
    
    # Port-based scoring
    dst_port = row.get(col_mapping.get('dst_port'), 0)
    if dst_port in [22, 23]:  # SSH/Telnet
        base_score += 0.1
    elif dst_port in [3128, 4499]:  # Proxy/DB ports
        base_score += 0.15
    
    # Protocol-based scoring
    protocol = str(row.get(col_mapping.get('protocol'), '')).strip().upper()
    if protocol == 'ICMP':
        base_score += 0.1  # ICMP often used for scanning
    
    return min(base_score, 1.0)

def extract_threat_actors(events: List[Dict], min_threat_score: float = 0.6) -> Dict[str, Dict]:
    """Extract and profile threat actors from events"""
    actor_profiles = defaultdict(lambda: {
        'total_events': 0,
        'malicious_events': 0,
        'threat_types': set(),
        'avg_threat_score': 0.0,
        'total_threat_score': 0.0,
        'first_seen': None,
        'last_seen': None,
        'target_ips': set(),
        'protocols': set()
    })
    
    for event in events:
        if event['threat_score'] >= min_threat_score:
            ip = event['src_ip']
            profile = actor_profiles[ip]
            
            profile['total_events'] += 1
            if event['is_malicious']:
                profile['malicious_events'] += 1
            
            profile['total_threat_score'] += event['threat_score']
            
            if event['threat_type']:
                profile['threat_types'].add(event['threat_type'])
            
            profile['target_ips'].add(event['dst_ip'])
            profile['protocols'].add(event['protocol'])
            
            timestamp = event['timestamp']
            if not profile['first_seen'] or timestamp < profile['first_seen']:
                profile['first_seen'] = timestamp
            if not profile['last_seen'] or timestamp > profile['last_seen']:
                profile['last_seen'] = timestamp
    
    # Calculate averages and convert sets to lists
    final_profiles = {}
    for ip, profile in actor_profiles.items():
        if profile['total_events'] > 0:
            profile['avg_threat_score'] = profile['total_threat_score'] / profile['total_events']
            profile['threat_types'] = list(profile['threat_types'])
            profile['target_ips'] = list(profile['target_ips'])
            profile['protocols'] = list(profile['protocols'])
            final_profiles[ip] = profile
    
    return final_profiles

def generate_security_report(events: List[Dict], threat_stats: Dict, actor_profiles: Dict) -> Dict:
    """Generate comprehensive security report"""
    total_events = len(events)
    malicious_events = len([e for e in events if e['is_malicious']])
    critical_events = len([e for e in events if e['threat_score'] > 0.8])
    
    # Risk assessment
    if critical_events > 10:
        risk_level = "CRITICAL"
    elif critical_events > 5:
        risk_level = "HIGH"
    elif malicious_events > 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    # Timeline analysis
    if events:
        event_df = pd.DataFrame(events)
        event_df['timestamp'] = pd.to_datetime(event_df['timestamp'])
        event_df['hour'] = event_df['timestamp'].dt.hour
        hourly_stats = event_df.groupby('hour')['threat_score'].agg(['count', 'mean']).to_dict()
    else:
        hourly_stats = {}
    
    # Generate recommendations
    recommendations = []
    if threat_stats.get('ddos', 0) > 0:
        recommendations.append("Implement DDoS protection and rate limiting")
    if threat_stats.get('sql_injection', 0) > 0:
        recommendations.append("Deploy Web Application Firewall (WAF)")
    if threat_stats.get('brute_force', 0) > 0:
        recommendations.append("Enforce MFA and account lockout policies")
    if len(actor_profiles) > 5:
        recommendations.append("Consider IP-based blocking and threat intelligence feeds")
    if critical_events > 0:
        recommendations.append("Escalate to incident response team immediately")
    
    return {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_events': total_events,
            'malicious_events': malicious_events,
            'critical_events': critical_events,
            'threat_actors': len(actor_profiles),
            'attack_percentage': round((malicious_events / total_events * 100), 2) if total_events > 0 else 0,
            'risk_level': risk_level
        },
        'threat_analysis': {
            'by_type': dict(threat_stats),
            'timeline': hourly_stats,
            'top_protocols': Counter([e['protocol'] for e in events if e['is_malicious']]).most_common(5)
        },
        'threat_actors': dict(list(actor_profiles.items())[:10]),  # Top 10 actors
        'mitre_mapping': {t: MITRE_TACTICS[t] for t in threat_stats.keys() if t in MITRE_TACTICS},
        'recommendations': recommendations,
        'metadata': {
            'analysis_duration': 'Real-time',
            'ai_enhanced': ai_pipeline is not None,
            'framework': 'MITRE ATT&CK',
            'confidence': 'HIGH' if ai_pipeline else 'MEDIUM'
        }
    }

def main_analysis(csv_path: Optional[str] = None, use_ai: bool = True, sample_size: int = 1000) -> Dict:
    """Main entry point for security analysis"""
    try:
        # Initialize AI if requested
        if use_ai:
            initialize_ai_model()
        
        # Load or generate data
        if csv_path:
            logger.info(f"Loading data from {csv_path}")
            try:
                # Try different encodings and separators
                df = pd.read_csv(csv_path, encoding='utf-8')
            except UnicodeDecodeError:
                try:
                    df = pd.read_csv(csv_path, encoding='latin-1')
                except:
                    df = pd.read_csv(csv_path, encoding='cp1252')
            except:
                # If comma separation fails, try other separators
                try:
                    df = pd.read_csv(csv_path, sep=';')
                except:
                    df = pd.read_csv(csv_path, sep='\t')
                    
            logger.info(f"Successfully loaded {len(df)} records")
            
        else:
            logger.info(f"Generating {sample_size} sample records")
            df = generate_sample_data(sample_size)
        
        # Perform analysis
        events, threat_stats = analyze_network_flows(df, use_ai)
        actor_profiles = extract_threat_actors(events, min_threat_score=0.5)  # Lower threshold for your data
        report = generate_security_report(events, threat_stats, actor_profiles)
        
        # Log summary for debugging
        malicious_events = len([e for e in events if e['is_malicious']])
        logger.info(f"Analysis summary: {malicious_events} malicious events, {len(threat_stats)} threat types, {len(actor_profiles)} threat actors")
        
        return {
            'success': True,
            'report': report,
            'events': events,
            'raw_data': df,
            'message': f"Analysis complete: {len(events)} events processed, {malicious_events} threats detected"
        }
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'error': str(e),
            'message': "Analysis failed - check logs for details"
        }

if __name__ == "__main__":
    result = main_analysis()
    if result['success']:
        print(f"✅ {result['message']}")
        print(f"Risk Level: {result['report']['summary']['risk_level']}")
        print(f"Malicious Events: {result['report']['summary']['malicious_events']}")
    else:
        print(f"❌ {result['message']}")