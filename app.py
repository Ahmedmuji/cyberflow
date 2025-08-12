#!/usr/bin/env python3
"""
Security Log Analyzer using Custom Log Processing and Llama for Threat Detection
Processes security logs, identifies threats, and extracts attacker IPs
"""

import re
import json
import logging
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional
import random
from collections import defaultdict, Counter
import hashlib
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variables
llama_pipeline = None

# Security patterns for threat detection
SECURITY_PATTERNS = {
    'ddos': r'(?i)(ddos|denial.of.service|flood|overwhelm)',
    'port_scan': r'(?i)(port.*scan|nmap|reconnaissance|probe)',
    'brute_force': r'(?i)(brute.?force|multiple.*fail|repeated.*attempt)',
    'malware': r'(?i)(malware|virus|trojan|backdoor|ransomware)',
    'sql_injection': r'(?i)(sql.*inject|union.*select|drop.*table)',
    'privilege_escalation': r'(?i)(privilege.*escalat|sudo|admin.*access)'
}

# Attack type mappings based on your CSV
ATTACK_MAPPINGS = {
    'Syn flooding': 'ddos',
    'UDP flooding': 'ddos', 
    'HTTP flooding': 'ddos',
    'Port scan': 'port_scan',
    'Brute force': 'brute_force',
    'SQL injection': 'sql_injection'
}

def initialize_llama_model(model_name: str = "microsoft/DialoGPT-medium") -> None:
    """Initialize Llama model from Hugging Face"""
    global llama_pipeline
    
    try:
        logger.info(f"Loading language model: {model_name}")
        device = 0 if torch.cuda.is_available() else -1
        
        llama_pipeline = pipeline(
            "text-generation",
            model=model_name,
            tokenizer=model_name,
            device=device,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            max_length=1024,
            do_sample=True,
            temperature=0.1,
            pad_token_id=50256
        )
        logger.info("Language model loaded successfully")
        
    except Exception as e:
        logger.error(f"Failed to load language model: {e}")
        llama_pipeline = None

def generate_test_network_data() -> pd.DataFrame:
    """Generate realistic test network flow data matching CSV format"""
    
    base_time = datetime.now() - timedelta(hours=24)
    data = []
    
    # Normal traffic
    normal_ips = ['192.168.1.100', '10.0.0.50', 'OPENSTACK_NET']
    ext_servers = ['EXT_SERVER', '203.0.113.15', '172.16.0.25']
    
    for i in range(100):
        timestamp = base_time + timedelta(minutes=random.randint(0, 1440))
        duration = random.uniform(10, 300)
        src_ip = random.choice(normal_ips)
        dst_ip = random.choice(ext_servers)
        
        data.append({
            'Date first seen': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'Duration': f"{duration:.3f}",
            'Proto': random.choice(['TCP  ', 'UDP  ', 'ICMP ']),
            'Src IP Addr': src_ip,
            'Src Pt': random.randint(1024, 65535),
            'Dst IP Addr': dst_ip,
            'Dst Pt': random.choice([80, 443, 22, 21, 25, 53]),
            'Packets': random.randint(10, 1000),
            'Bytes': f"{random.uniform(1, 10):.1f} M",
            'Flows': 1,
            'Flags': random.choice(['.AP...', '...P..', '.A....', 'S.....', 'F.....']),
            'Tos': 0,
            'class': 'normal',
            'attackType': '---',
            'attackID': '---',
            'attackDescription': '---'
        })
    
    # Attack traffic
    attacker_ips = ['45.123.45.67', '198.51.100.99', '203.0.113.254']
    attack_types = ['Syn flooding', 'UDP flooding', 'Port scan', 'Brute force', 'HTTP flooding']
    
    for i in range(50):
        timestamp = base_time + timedelta(minutes=random.randint(0, 1440))
        attack_type = random.choice(attack_types)
        attacker_ip = random.choice(attacker_ips)
        
        if 'flooding' in attack_type:
            packets = random.randint(5000, 50000)
            bytes_val = f"{random.uniform(50, 500):.1f} M"
            duration = random.uniform(1, 30)
        elif 'scan' in attack_type:
            packets = random.randint(1, 10)
            bytes_val = f"{random.uniform(0.1, 1):.1f} M"
            duration = random.uniform(0.1, 5)
        else:
            packets = random.randint(100, 2000)
            bytes_val = f"{random.uniform(1, 20):.1f} M"
            duration = random.uniform(5, 120)
        
        data.append({
            'Date first seen': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'Duration': f"{duration:.3f}",
            'Proto': 'TCP  ' if 'TCP' in attack_type or 'Syn' in attack_type else 'UDP  ',
            'Src IP Addr': attacker_ip,
            'Src Pt': random.randint(1024, 65535),
            'Dst IP Addr': random.choice(['OPENSTACK_NET', '192.168.1.100']),
            'Dst Pt': random.choice([80, 443, 22, 21, 25]),
            'Packets': packets,
            'Bytes': bytes_val,
            'Flows': 1,
            'Flags': '.AP...' if 'Syn' in attack_type else random.choice(['.AP...', '...P..', '.A....']),
            'Tos': 0,
            'class': 'attack',
            'attackType': attack_type,
            'attackID': f"ATK_{random.randint(1000, 9999)}",
            'attackDescription': f"{attack_type} attack from {attacker_ip}"
        })
    
    return pd.DataFrame(data)

def get_organization_context() -> str:
    """Return organization security context"""
    return """
    TechCorp Financial Services - Network Security Profile:
    - High-value target for financially motivated cybercriminals
    - 24/7 operations with peak hours 9 AM - 6 PM EST
    - Critical assets: customer portal, payment systems, databases
    - Known threats: DDoS, credential attacks, web exploits
    - Compliance: PCI DSS, SOX, GLBA requirements
    """

def analyze_network_flows(df: pd.DataFrame) -> List[Dict]:
    """Analyze network flow data for security threats"""
    security_events = []
    
    for _, row in df.iterrows():
        event = {
            'timestamp': row['Date first seen'],
            'source_ip': row['Src IP Addr'],
            'dest_ip': row['Dst IP Addr'],
            'protocol': row['Proto'].strip(),
            'src_port': row['Src Pt'],
            'dst_port': row['Dst Pt'],
            'packets': row['Packets'],
            'bytes': row['Bytes'],
            'duration': float(row['Duration']),
            'attack_type': row['attackType'],
            'attack_class': row['class'],
            'threat_score': 0.0,
            'is_malicious': False,
            'threat_indicators': []
        }
        
        # Determine threat level
        if row['class'] == 'attack':
            event['threat_score'] = 0.8
            event['is_malicious'] = True
            event['threat_indicators'] = [ATTACK_MAPPINGS.get(row['attackType'], 'unknown_attack')]
        else:
            # Analyze normal traffic for anomalies
            score = 0.1
            
            # High packet/byte ratios
            if isinstance(row['Packets'], int) and row['Packets'] > 10000:
                score += 0.3
                event['threat_indicators'].append('high_volume')
            
            # Suspicious ports
            if row['Dst Pt'] in [22, 3389, 1433, 3306]:  # SSH, RDP, SQL Server, MySQL
                score += 0.2
                event['threat_indicators'].append('sensitive_port')
            
            # External to internal traffic
            if 'EXT_' in str(row['Src IP Addr']) and 'OPENSTACK' in str(row['Dst IP Addr']):
                score += 0.1
            
            event['threat_score'] = min(score, 1.0)
            event['is_malicious'] = score >= 0.6
        
        security_events.append(event)
    
    return security_events

def analyze_with_llama_flows(security_events: List[Dict], org_context: str) -> List[Dict]:
    """Analyze network flow events using Llama model"""
    global llama_pipeline
    
    if not llama_pipeline:
        return enhanced_flow_analysis(security_events, org_context)
    
    analyzed_events = []
    
    for event in security_events:
        prompt = f"""Security Context: {org_context}

Network Flow Analysis:
Time: {event['timestamp']}
Source: {event['source_ip']}:{event['src_port']} -> Dest: {event['dest_ip']}:{event['dst_port']}
Protocol: {event['protocol']}, Packets: {event['packets']}, Bytes: {event['bytes']}
Duration: {event['duration']}s, Attack Type: {event['attack_type']}

Threat assessment (0.0-1.0): """
        
        try:
            response = llama_pipeline(prompt, max_new_tokens=50, temperature=0.1)[0]['generated_text']
            
            # Extract threat score
            score_match = re.search(r'([0-9.]+)', response.split(prompt)[-1])
            if score_match:
                event['threat_score'] = min(float(score_match.group(1)), 1.0)
                event['is_malicious'] = event['threat_score'] >= 0.6
                
        except Exception as e:
            logger.error(f"Llama analysis failed: {e}")
            # Keep original scores
        
        analyzed_events.append(event)
    
    return analyzed_events

def enhanced_flow_analysis(security_events: List[Dict], org_context: str) -> List[Dict]:
    """Enhanced rule-based analysis for network flows"""
    
    # Calculate baseline metrics
    packet_counts = [e['packets'] for e in security_events if isinstance(e['packets'], int)]
    avg_packets = sum(packet_counts) / len(packet_counts) if packet_counts else 100
    
    for event in security_events:
        if event['attack_class'] == 'attack':
            continue  # Already analyzed
        
        score = 0.1
        
        # Volume-based detection
        if isinstance(event['packets'], int):
            if event['packets'] > avg_packets * 10:
                score += 0.4
                event['threat_indicators'].append('volume_anomaly')
        
        # Duration analysis
        if event['duration'] > 3600:  # > 1 hour
            score += 0.2
        elif event['duration'] < 0.1:  # Very short
            score += 0.1
        
        # Protocol analysis
        if event['protocol'] == 'ICMP':
            score += 0.2  # ICMP can be used for reconnaissance
        
        event['threat_score'] = min(score, 1.0)
        event['is_malicious'] = score >= 0.6
    
    return security_events

def extract_attacker_ips_flows(security_events: List[Dict], threshold: float = 0.6) -> Set[str]:
    """Extract attacker IPs from network flow analysis"""
    ip_metrics = defaultdict(lambda: {'events': 0, 'threat_sum': 0, 'malicious_count': 0})
    
    for event in security_events:
        ip = event['source_ip']
        if ip and ip not in ['---', 'unknown']:
            ip_metrics[ip]['events'] += 1
            ip_metrics[ip]['threat_sum'] += event['threat_score']
            if event['is_malicious']:
                ip_metrics[ip]['malicious_count'] += 1
    
    attacker_ips = set()
    for ip, metrics in ip_metrics.items():
        avg_threat = metrics['threat_sum'] / metrics['events']
        malicious_ratio = metrics['malicious_count'] / metrics['events']
        
        if (avg_threat >= threshold or 
            malicious_ratio >= 0.5 or 
            metrics['events'] >= 20):
            attacker_ips.add(ip)
    
    return attacker_ips

def generate_threat_report_flows(security_events: List[Dict], attacker_ips: Set[str]) -> Dict:
    """Generate threat report for network flow data"""
    
    total_events = len(security_events)
    attack_events = [e for e in security_events if e['attack_class'] == 'attack']
    high_threat_events = [e for e in security_events if e['threat_score'] >= 0.7]
    
    # Protocol analysis
    proto_stats = defaultdict(int)
    attack_types = defaultdict(int)
    
    for event in attack_events:
        proto_stats[event['protocol']] += 1
        if event['attack_type'] != '---':
            attack_types[event['attack_type']] += 1
    
    # Attacker profiles
    attacker_profiles = {}
    for ip in attacker_ips:
        ip_events = [e for e in security_events if e['source_ip'] == ip]
        if ip_events:
            attacker_profiles[ip] = {
                'total_flows': len(ip_events),
                'attack_flows': len([e for e in ip_events if e['attack_class'] == 'attack']),
                'avg_threat_score': sum(e['threat_score'] for e in ip_events) / len(ip_events),
                'protocols': list(set(e['protocol'] for e in ip_events)),
                'attack_types': list(set(e['attack_type'] for e in ip_events if e['attack_type'] != '---')),
                'first_seen': min(e['timestamp'] for e in ip_events),
                'last_seen': max(e['timestamp'] for e in ip_events)
            }
    
    # Recommendations
    recommendations = []
    if len(attacker_ips) > 0:
        recommendations.append("Block identified attacker IP addresses at firewall")
    if attack_types.get('Syn flooding', 0) > 0:
        recommendations.append("Implement SYN flood protection and rate limiting")
    if attack_types.get('Port scan', 0) > 0:
        recommendations.append("Deploy intrusion detection system (IDS)")
    if len(attack_events) > total_events * 0.1:
        recommendations.append("Escalate to incident response team")
    
    return {
        'analysis_timestamp': datetime.now().isoformat(),
        'summary': {
            'total_flows': total_events,
            'attack_flows': len(attack_events),
            'high_threat_flows': len(high_threat_events),
            'attacker_ips_count': len(attacker_ips),
            'attack_percentage': round((len(attack_events) / total_events) * 100, 2) if total_events > 0 else 0
        },
        'attack_analysis': {
            'attack_types': dict(attack_types),
            'protocol_distribution': dict(proto_stats),
            'timeline_analysis': 'Available in detailed view'
        },
        'attacker_intelligence': {
            'identified_attackers': list(attacker_ips),
            'attacker_profiles': attacker_profiles
        },
        'recommendations': recommendations,
        'risk_level': 'HIGH' if len(attack_events) > 10 else 'MEDIUM' if len(attack_events) > 5 else 'LOW'
    }

def analyze_csv_logs(csv_file_path: str = None) -> Dict:
    """Main function to analyze CSV log data"""
    logger.info("Starting Network Flow Security Analysis")
    
    # Initialize model
    try:
        initialize_llama_model()
    except Exception as e:
        logger.warning(f"Model initialization failed: {e}")
    
    # Load or generate data
    if csv_file_path:
        logger.info(f"Loading CSV file: {csv_file_path}")
        df = pd.read_csv(csv_file_path)
    else:
        logger.info("Generating test network flow data...")
        df = generate_test_network_data()
    
    logger.info(f"Analyzing {len(df)} network flows")
    
    # Analyze flows
    security_events = analyze_network_flows(df)
    
    # AI/ML analysis
    organization_context = get_organization_context()
    analyzed_events = analyze_with_llama_flows(security_events, organization_context)
    
    # Extract attackers
    attacker_ips = extract_attacker_ips_flows(analyzed_events)
    
    # Generate report
    report = generate_threat_report_flows(analyzed_events, attacker_ips)
    
    logger.info("Analysis Complete!")
    logger.info(f"Identified {len(attacker_ips)} attacker IPs: {list(attacker_ips)[:3]}")
    
    return {
        'report': report,
        'events': analyzed_events,
        'attackers': list(attacker_ips),
        'dataframe': df
    }

def print_summary_report(report: Dict) -> None:
    """Print concise threat report"""
    print("\n" + "="*60)
    print("NETWORK SECURITY THREAT ANALYSIS")
    print("="*60)
    
    summary = report['summary']
    print(f"Total Flows: {summary['total_flows']:,}")
    print(f"Attack Flows: {summary['attack_flows']:,} ({summary['attack_percentage']}%)")
    print(f"Attacker IPs: {summary['attacker_ips_count']}")
    print(f"Risk Level: {report['risk_level']}")
    print()
    
    if report['attack_analysis']['attack_types']:
        print("TOP ATTACKS:")
        for attack, count in list(report['attack_analysis']['attack_types'].items())[:3]:
            print(f"  {attack}: {count}")
        print()
    
    if report['recommendations']:
        print("RECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'][:3], 1):
            print(f"  {i}. {rec}")
    
    print("="*60)

def main():
    """Main execution function"""
    result = analyze_csv_logs()
    print_summary_report(result['report'])
    return result

if __name__ == "__main__":
    main()