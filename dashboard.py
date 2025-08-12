#!/usr/bin/env python3
"""
Streamlit Frontend for Security Log Analyzer
Run with: streamlit run streamlit_app.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import os
from typing import List, Dict

# Import the main analyzer
try:
    from app import (
        analyze_csv_logs, generate_test_network_data, get_organization_context,
        analyze_network_flows, analyze_with_llama_flows, enhanced_flow_analysis,
        extract_attacker_ips_flows, generate_threat_report_flows
    )
except ImportError:
    st.error("Please ensure security_analyzer.py is in the same directory!")
    st.stop()

# Page configuration
st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .attack-card {
        background-color: #fee;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #d32f2f;
    }
    .safe-card {
        background-color: #f0f8f0;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #2e7d32;
    }
</style>
""", unsafe_allow_html=True)

def main():
    st.title("🛡️ Security Log Analyzer")
    st.markdown("**AI-Powered Network Security Threat Detection**")
    
    # Sidebar
    st.sidebar.header("Configuration")
    
    uploaded_file = st.sidebar.file_uploader(
        "Upload CSV Log File",
        type=['csv'],
        help="Upload a CSV file with network flow data"
    )
    
    use_ai = st.sidebar.checkbox("Use AI Analysis (Llama)", value=True)
    threat_threshold = st.sidebar.slider("Threat Threshold", 0.0, 1.0, 0.6, 0.1)
    
    if st.sidebar.button("Generate Test Data"):
        st.session_state['test_data'] = True
    
    col1, col2 = st.columns([2, 1])
    
    with col2:
        st.info("**Organization Context**\n\n" + get_organization_context())
    
    with col1:
        if uploaded_file is not None:
            df = pd.read_csv(uploaded_file)
            st.success(f"Loaded {len(df)} records from uploaded file")
            process_data(df, use_ai, threat_threshold)
        elif st.session_state.get('test_data', False):
            with st.spinner("Generating test data and analyzing..."):
                df = generate_test_network_data()
                st.success(f"Generated {len(df)} test network flow records")
                process_data(df, use_ai, threat_threshold)
        else:
            st.markdown("""
            ### Welcome to Security Log Analyzer
            
            This tool analyzes network flow data to identify security threats using:
            - **AI-powered analysis** with Llama models
            - **Pattern recognition** for known attack signatures  
            - **Behavioral analysis** to detect anomalies
            - **Real-time threat intelligence**
            
            **Get Started:**
            1. Upload a CSV file with your network flow data, or
            2. Click "Generate Test Data" to see a demo
            """)

def process_data(df: pd.DataFrame, use_ai: bool, threat_threshold: float):
    with st.spinner("Analyzing security events..."):
        temp_csv = "temp_analysis.csv"
        df.to_csv(temp_csv, index=False)
        
        try:
            security_events = analyze_network_flows(df)
            if use_ai:
                analyzed_events = analyze_with_llama_flows(security_events, get_organization_context())
            else:
                analyzed_events = enhanced_flow_analysis(security_events, get_organization_context())
            attacker_ips = extract_attacker_ips_flows(analyzed_events, threat_threshold)
            report = generate_threat_report_flows(analyzed_events, attacker_ips)
            if os.path.exists(temp_csv):
                os.remove(temp_csv)
        except Exception as e:
            st.error(f"Analysis failed: {e}")
            return
    
    display_results(df, analyzed_events, report, list(attacker_ips))

def display_results(df: pd.DataFrame, events: List[Dict], report: Dict, attacker_ips: List[str]):
    st.header("📊 Security Analysis Results")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Flows", f"{report['summary']['total_flows']:,}")
    with col2:
        st.metric("Attack Flows", f"{report['summary']['attack_flows']:,}",
                  delta=f"{report['summary']['attack_percentage']}%", delta_color="inverse")
    with col3:
        st.metric("Threat IPs", len(attacker_ips))
    with col4:
        risk_color = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
        st.metric("Risk Level", f"{risk_color.get(report['risk_level'], '⚪')} {report['risk_level']}")
    
    st.header("📈 Threat Analysis")
    
    if report['attack_analysis']['attack_types']:
        col1, col2 = st.columns(2)
        with col1:
            attack_data = report['attack_analysis']['attack_types']
            fig = px.pie(values=list(attack_data.values()), names=list(attack_data.keys()),
                         title="Attack Types Distribution")
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            proto_data = report['attack_analysis']['protocol_distribution']
            fig = px.bar(x=list(proto_data.keys()), y=list(proto_data.values()),
                         title="Protocols Used in Attacks")
            st.plotly_chart(fig, use_container_width=True)
    
    if events:
        st.subheader("🕒 Timeline Analysis")
        event_df = pd.DataFrame(events)
        event_df['timestamp'] = pd.to_datetime(event_df['timestamp'])
        event_df['hour'] = event_df['timestamp'].dt.hour
        hourly_threats = event_df[event_df['threat_score'] >= 0.6].groupby('hour').size()
        fig = px.line(x=hourly_threats.index, y=hourly_threats.values,
                      title="Hourly Threat Activity",
                      labels={'x': 'Hour of Day', 'y': 'Threat Events'})
        st.plotly_chart(fig, use_container_width=True)
    
    if attacker_ips:
        st.header("🎯 Attacker Intelligence")
        for ip in attacker_ips[:5]:
            profile = report['attacker_intelligence']['attacker_profiles'].get(ip, {})
            with st.expander(f"🚨 Attacker IP: {ip}"):
                col1, col2, col3 = st.columns(3)
                with col1: st.metric("Total Flows", profile.get('total_flows', 0))
                with col2: st.metric("Attack Flows", profile.get('attack_flows', 0))
                with col3: st.metric("Threat Score", f"{profile.get('avg_threat_score', 0):.2f}")
                if profile.get('attack_types'):
                    st.write("**Attack Types:**", ", ".join(profile['attack_types']))
                if profile.get('protocols'):
                    st.write("**Protocols:**", ", ".join(profile['protocols']))
                st.write(f"**Active Period:** {profile.get('first_seen', 'Unknown')} to {profile.get('last_seen', 'Unknown')}")
    
    st.header("💡 Security Recommendations")
    if report['recommendations']:
        for i, rec in enumerate(report['recommendations'], 1):
            st.write(f"{i}. {rec}")
    else:
        st.success("No immediate security recommendations - system appears secure")
    
    st.header("📋 Detailed Analysis")
    tab1, tab2, tab3 = st.tabs(["Security Events", "Network Flows", "Raw Data"])
    
    with tab1:
        security_df = pd.DataFrame([e for e in events if e['threat_score'] >= 0.3])
        if not security_df.empty:
            st.dataframe(security_df[['timestamp', 'source_ip', 'dest_ip', 'protocol', 'attack_type', 'threat_score', 'is_malicious']],
                         use_container_width=True)
            st.download_button(
                label="⬇ Download Security Events CSV",
                data=security_df.to_csv(index=False),
                file_name="security_events.csv",
                mime="text/csv"
            )
        else:
            st.info("No significant security events detected")
    
    with tab2:
        if 'protocol' in df.columns and 'source_ip' in df.columns:
            flow_summary = (
                df.groupby(['protocol', 'source_ip'])
                .size()
                .reset_index(name='flow_count')
                .sort_values(by='flow_count', ascending=False)
            )
            st.dataframe(flow_summary, use_container_width=True)
            st.download_button(
                label="⬇ Download Flow Summary CSV",
                data=flow_summary.to_csv(index=False),
                file_name="network_flows_summary.csv",
                mime="text/csv"
            )
        else:
            st.warning("Protocol or source_ip column not found in data.")
    
    with tab3:
        st.dataframe(df, use_container_width=True)
        st.download_button(
            label="⬇ Download Raw Data CSV",
            data=df.to_csv(index=False),
            file_name="raw_network_data.csv",
            mime="text/csv"
        )

if __name__ == "__main__":
    main()
