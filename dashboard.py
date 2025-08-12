#!/usr/bin/env python3
"""
Professional Security Operations Dashboard
Frontend for Security Log Analyzer
Run with: streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
from datetime import datetime, timedelta
import json

# Import backend functions
try:
    from app import (
        main_analysis, generate_sample_data, MITRE_TACTICS,
        initialize_ai_model
    )
except ImportError:
    st.error("❌ Security analyzer backend not found! Please ensure security_analyzer.py is in the same directory.")
    st.stop()

# Page Configuration
st.set_page_config(
    page_title="Enterprise Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional CSS Styling
st.markdown("""
<style>
    /* Main header styling */
    .main-header {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    /* Metric cards */
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 5px solid #007bff;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        margin-bottom: 1rem;
    }
    
    /* Threat level indicators */
    .threat-critical { border-left-color: #dc3545 !important; }
    .threat-high { border-left-color: #fd7e14 !important; }
    .threat-medium { border-left-color: #ffc107 !important; }
    .threat-low { border-left-color: #28a745 !important; }
    
    /* MITRE section styling */
    .mitre-section {
        background: #f8f9fa;
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #dee2e6;
        margin: 1rem 0;
    }
    
    /* Attacker profile cards */
    .attacker-card {
        background: #fff5f5;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #e53e3e;
        margin: 0.5rem 0;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display:none;}
</style>
""", unsafe_allow_html=True)

def render_header():
    """Render professional dashboard header"""
    st.markdown("""
    <div class="main-header">
        <h1 style="color: white; margin: 0; font-size: 2.5rem;">🛡️ Enterprise Security Operations Center</h1>
        <p style="color: #e3f2fd; margin: 0.5rem 0 0 0; font-size: 1.1rem;">
            AI-Powered Threat Detection | MITRE ATT&CK Framework | Real-time Security Analytics
        </p>
    </div>
    """, unsafe_allow_html=True)

def render_executive_dashboard(report_data: dict):
    """Render executive-level security metrics"""
    st.markdown("### 📊 Executive Security Dashboard")
    
    summary = report_data['summary']
    
    # Key Performance Indicators
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🔍 Total Events",
            value=f"{summary['total_events']:,}",
            help="Total network flows analyzed in current timeframe"
        )
    
    with col2:
        threat_delta = f"+{summary['attack_percentage']:.1f}%" if summary['attack_percentage'] > 0 else "0%"
        st.metric(
            label="⚠️ Threat Events",
            value=f"{summary['malicious_events']:,}",
            delta=threat_delta,
            delta_color="inverse"
        )
    
    with col3:
        st.metric(
            label="🚨 Critical Threats",
            value=summary['critical_events'],
            delta="🔴 HIGH" if summary['critical_events'] > 5 else "🟢 NORMAL",
            delta_color="off"
        )
    
    with col4:
        risk_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        risk_icon = risk_colors.get(summary['risk_level'], "⚪")
        st.metric(
            label="🎯 Risk Level",
            value=f"{risk_icon} {summary['risk_level']}"
        )

def render_threat_analysis(report_data: dict):
    """Render threat analysis visualizations"""
    st.markdown("### 📈 Threat Intelligence Analysis")
    
    threat_analysis = report_data['threat_analysis']
    
    if threat_analysis['by_type']:
        col1, col2 = st.columns(2)
        
        with col1:
            # Threat types distribution
            threat_data = threat_analysis['by_type']
            fig_pie = px.pie(
                values=list(threat_data.values()),
                names=list(threat_data.keys()),
                title="🎯 Attack Types Distribution",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig_pie.update_layout(showlegend=True, height=400)
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            # Protocol usage in attacks
            if threat_analysis.get('top_protocols'):
                protocols = [item[0] for item in threat_analysis['top_protocols']]
                counts = [item[1] for item in threat_analysis['top_protocols']]
                
                fig_bar = px.bar(
                    x=protocols,
                    y=counts,
                    title="🌐 Attack Protocols Distribution",
                    labels={'x': 'Protocol', 'y': 'Attack Count'},
                    color=counts,
                    color_continuous_scale='Reds'
                )
                fig_bar.update_layout(height=400)
                st.plotly_chart(fig_bar, use_container_width=True)
    
    else:
        st.info("🟢 No significant threats detected - system operating normally")

def render_timeline_analysis(events_data: list):
    """Render threat timeline analysis"""
    st.markdown("### ⏰ Threat Timeline Analysis")
    
    if not events_data:
        st.info("No timeline data available")
        return
    
    # Convert events to DataFrame
    df = pd.DataFrame([e for e in events_data if e.get('is_malicious', False)])
    
    if df.empty:
        st.info("🟢 No malicious activity detected in timeline")
        return
    
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['date'] = df['timestamp'].dt.date
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Hourly threat distribution
        hourly_threats = df.groupby('hour').size().reset_index(name='threats')
        
        fig_hourly = px.line(
            hourly_threats,
            x='hour',
            y='threats',
            title='⏰ Hourly Threat Activity',
            markers=True
        )
        fig_hourly.update_xaxes(title_text="Hour of Day")
        fig_hourly.update_yaxes(title="Number of Threats")
        fig_hourly.update_traces(line_color='#e74c3c')
        st.plotly_chart(fig_hourly, use_container_width=True)
    
    with col2:
        # Threat score distribution
        fig_scores = px.histogram(
            df,
            x='threat_score',
            nbins=20,
            title='📊 Threat Score Distribution',
            color_discrete_sequence=['#3498db']
        )
        fig_scores.update_xaxes(title="Threat Score")
        fig_scores.update_yaxes(title="Frequency")
        st.plotly_chart(fig_scores, use_container_width=True)

def render_mitre_framework(report_data: dict):
    """Render MITRE ATT&CK framework analysis"""
    st.markdown("### 🛡️ MITRE ATT&CK Framework Analysis")
    
    mitre_mapping = report_data.get('mitre_mapping', {})
    
    if not mitre_mapping:
        st.success("🟢 No MITRE ATT&CK techniques detected - defensive posture strong")
        return
    
    for threat_type, mitre_info in mitre_mapping.items():
        threat_count = report_data['threat_analysis']['by_type'].get(threat_type, 0)
        
        with st.expander(f"⚠️ {threat_type.upper().replace('_', ' ')} - {threat_count} incidents"):
            col1, col2 = st.columns([1, 2])
            
            with col1:
                st.markdown(f"""
                **🎯 MITRE Details:**
                - **Tactic:** {mitre_info.get('tactic', 'Unknown')}
                - **Technique:** {mitre_info.get('technique', 'Unknown')}
                - **Severity:** {mitre_info.get('severity', 'MEDIUM')}
                - **Incidents:** {threat_count}
                """)
            
            with col2:
                st.markdown("**🛠️ Recommended Countermeasures:**")
                countermeasures = mitre_info.get('countermeasures', [])
                for i, measure in enumerate(countermeasures, 1):
                    priority = "🔴 Critical" if i <= 2 else "🟡 Important"
                    st.markdown(f"{i}. **{priority}:** {measure}")

def render_threat_actors(report_data: dict):
    """Render threat actor intelligence"""
    st.markdown("### 🎭 Threat Actor Intelligence")
    
    threat_actors = report_data.get('threat_actors', {})
    
    if not threat_actors:
        st.info("🟢 No threat actors identified in current analysis")
        return
    
    # Sort actors by threat score
    sorted_actors = sorted(threat_actors.items(), 
                          key=lambda x: x[1]['avg_threat_score'], reverse=True)
    
    for i, (ip, profile) in enumerate(sorted_actors[:5], 1):
        threat_level = "🔴 CRITICAL" if profile['avg_threat_score'] > 0.8 else \
                      "🟠 HIGH" if profile['avg_threat_score'] > 0.6 else "🟡 MEDIUM"
        
        with st.expander(f"🚨 Threat Actor #{i}: {ip} - {threat_level}"):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Events", profile['total_events'])
                st.metric("Malicious Events", profile['malicious_events'])
            
            with col2:
                st.metric("Avg Threat Score", f"{profile['avg_threat_score']:.2f}")
                st.metric("Target IPs", len(profile.get('target_ips', [])))
            
            with col3:
                st.markdown("**Attack Types:**")
                for attack_type in profile.get('threat_types', []):
                    st.markdown(f"• {attack_type.replace('_', ' ').title()}")
                
                st.markdown("**Protocols Used:**")
                for protocol in profile.get('protocols', []):
                    st.markdown(f"• {protocol}")

def render_security_recommendations(report_data: dict):
    """Render security recommendations"""
    st.markdown("### 💡 Security Recommendations")
    
    recommendations = report_data.get('recommendations', [])
    
    if not recommendations:
        st.success("🟢 No immediate security recommendations - system appears secure")
        return
    
    priority_levels = ["🔴 CRITICAL", "🟠 HIGH", "🟡 MEDIUM", "🔵 LOW"]
    
    for i, recommendation in enumerate(recommendations, 1):
        priority = priority_levels[min(i-1, len(priority_levels)-1)]
        
        st.markdown(f"""
        <div class="metric-card">
            <strong>{priority} Priority {i}:</strong><br>
            {recommendation}
        </div>
        """, unsafe_allow_html=True)

def render_detailed_analysis(events_data: list, raw_data: pd.DataFrame):
    """Render detailed analysis tables"""
    st.markdown("### 📋 Detailed Security Analysis")
    
    tab1, tab2, tab3 = st.tabs(["🚨 Security Events", "📊 Flow Analysis", "📄 Raw Data"])
    
    with tab1:
        # Security events table
        security_events = [e for e in events_data if e.get('threat_score', 0) > 0.3]
        
        if security_events:
            events_df = pd.DataFrame(security_events)
            display_columns = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 
                             'threat_type', 'threat_score', 'is_malicious']
            
            # Filter existing columns
            available_columns = [col for col in display_columns if col in events_df.columns]
            
            st.dataframe(
                events_df[available_columns].sort_values('threat_score', ascending=False),
                use_container_width=True,
                height=400
            )
            
            # Download button
            csv_data = events_df[available_columns].to_csv(index=False)
            st.download_button(
                label="⬇️ Download Security Events",
                data=csv_data,
                file_name=f"security_events_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                mime="text/csv"
            )
        else:
            st.info("No significant security events to display")
    
    with tab2:
        # Network flow analysis
        if not raw_data.empty:
            st.markdown("**Top Source IPs by Event Count:**")
            if 'Src IP Addr' in raw_data.columns:
                top_sources = raw_data['Src IP Addr'].value_counts().head(10)
                st.bar_chart(top_sources)
            
            st.markdown("**Protocol Distribution:**")
            if 'Proto' in raw_data.columns:
                proto_dist = raw_data['Proto'].value_counts()
                st.bar_chart(proto_dist)
            
            # Summary statistics
            st.markdown("**Flow Summary:**")
            summary_stats = {
                'Total Flows': len(raw_data),
                'Unique Source IPs': raw_data['Src IP Addr'].nunique() if 'Src IP Addr' in raw_data.columns else 0,
                'Unique Destination IPs': raw_data['Dst IP Addr'].nunique() if 'Dst IP Addr' in raw_data.columns else 0,
                'Time Span': f"{raw_data['Date first seen'].min()} to {raw_data['Date first seen'].max()}" if 'Date first seen' in raw_data.columns else "Unknown"
            }
            
            for key, value in summary_stats.items():
                st.metric(key, value)
    
    with tab3:
        # Raw data view
        st.markdown("**Complete Dataset:**")
        st.dataframe(raw_data, use_container_width=True, height=400)
        
        # Download raw data
        raw_csv = raw_data.to_csv(index=False)
        st.download_button(
            label="⬇️ Download Raw Data",
            data=raw_csv,
            file_name=f"network_flows_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            mime="text/csv"
        )

def render_sidebar():
    """Render sidebar configuration"""
    with st.sidebar:
        st.markdown("### ⚙️ Security Analysis Configuration")
        
        # File upload
        uploaded_file = st.file_uploader(
            "📁 Upload Network Logs",
            type=['csv'],
            help="Upload CSV file containing network flow data"
        )
        
        # Analysis options
        st.markdown("### 🔧 Analysis Settings")
        use_ai = st.checkbox("🤖 Enable AI Analysis", value=True, 
                           help="Use AI models for enhanced threat detection")
        
        threat_threshold = st.slider(
            "🎯 Threat Sensitivity", 
            min_value=0.1, 
            max_value=1.0, 
            value=0.6, 
            step=0.1,
            help="Minimum threat score for event classification"
        )
        
        sample_size = st.slider(
            "📊 Sample Data Size",
            min_value=100,
            max_value=5000,
            value=1000,
            step=100,
            help="Number of sample records to generate"
        )
        
        # Action buttons
        st.markdown("### 🚀 Actions")
        analyze_sample = st.button("🔍 Analyze Sample Data", type="primary")
        
        # System info
        st.markdown("---")
        st.markdown("### ℹ️ System Information")
        st.info(f"""
        **SOC Platform v2.0**
        - Real-time Analysis: ✅
        - MITRE ATT&CK: ✅
        - AI Enhancement: {'✅' if use_ai else '❌'}
        - Last Update: {datetime.now().strftime('%H:%M:%S')}
        """)
        
        return uploaded_file, use_ai, threat_threshold, sample_size, analyze_sample

def main():
    """Main dashboard application"""
    render_header()
    
    # Sidebar configuration
    uploaded_file, use_ai, threat_threshold, sample_size, analyze_sample = render_sidebar()
    
    # Main analysis logic
    if uploaded_file is not None or analyze_sample:
        with st.spinner("🔄 Performing security analysis..."):
            try:
                if uploaded_file:
                    # Save uploaded file temporarily with proper handling
                    temp_path = f"temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    
                    # Write the uploaded content to temp file
                    with open(temp_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    
                    # Try to load and preview the data
                    try:
                        preview_df = pd.read_csv(temp_path).head()
                        st.info(f"📁 File preview - Columns detected: {list(preview_df.columns)[:5]}...")
                    except:
                        st.warning("⚠️ File format detection in progress...")
                    
                    result = main_analysis(csv_path=temp_path, use_ai=use_ai)
                    
                    # Clean up temp file
                    import os
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                    
                    if result['success']:
                        st.success(f"✅ File analyzed successfully: {len(result['raw_data'])} records processed")
                    else:
                        st.error(f"❌ Analysis failed: {result.get('message', 'Unknown error')}")
                        
                else:
                    result = main_analysis(use_ai=use_ai, sample_size=sample_size)
                    
                    if result['success']:
                        st.success(f"✅ Sample data analyzed: {sample_size} records generated and processed")
                    else:
                        st.error(f"❌ Analysis failed: {result.get('message', 'Unknown error')}")
                
                if result['success']:
                    # Show quick stats
                    malicious_count = len([e for e in result['events'] if e.get('is_malicious', False)])
                    st.metric("🚨 Threats Detected", malicious_count, 
                             delta=f"Risk: {result['report']['summary']['risk_level']}")
                    
                    # Render all dashboard components
                    render_executive_dashboard(result['report'])
                    
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        render_threat_analysis(result['report'])
                        render_timeline_analysis(result['events'])
                    
                    with col2:
                        render_mitre_framework(result['report'])
                        render_threat_actors(result['report'])
                    
                    render_security_recommendations(result['report'])
                    render_detailed_analysis(result['events'], result['raw_data'])
                    
                    # Analysis metadata
                    with st.expander("📋 Analysis Metadata"):
                        metadata = result['report'].get('metadata', {})
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("Framework", metadata.get('framework', 'MITRE ATT&CK'))
                        with col2:
                            st.metric("AI Enhanced", "Yes" if metadata.get('ai_enhanced') else "No")
                        with col3:
                            st.metric("Confidence", metadata.get('confidence', 'High'))
                        
                        # Show data format info
                        st.info(f"""
                        **Analysis Details:**
                        - Total Records: {len(result['raw_data']):,}
                        - Threat Events: {malicious_count:,}
                        - Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                        - Data Format: Auto-detected CSV structure
                        """)
                
            except Exception as e:
                st.error(f"❌ Critical error during analysis: {str(e)}")
                with st.expander("🔍 Error Details"):
                    st.code(str(e))
                    import traceback
                    st.code(traceback.format_exc())
    
    else:
        # Welcome screen
        st.markdown("""
        ## 🚀 Welcome to Enterprise Security Operations Center
        
        Professional-grade security analytics platform featuring:
        
        ### 🔥 Core Capabilities
        - **🤖 AI-Powered Detection:** Advanced machine learning for threat identification
        - **🛡️ MITRE ATT&CK Integration:** Industry-standard threat classification
        - **⚡ Real-time Analysis:** Instant processing of network flow data
        - **📊 Executive Dashboards:** C-suite ready security insights
        
        ### 🎯 Advanced Features
        - **Threat Actor Profiling:** Identify and track malicious entities
        - **Timeline Analysis:** Understand attack patterns over time
        - **Risk Assessment:** Automated security posture evaluation
        - **Countermeasure Recommendations:** Actionable security improvements
        """)
        
        # Feature showcase
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            #### 🔍 Threat Detection
            - DDoS attack identification
            - Port scanning detection
            - Brute force recognition
            - SQL injection analysis
            - Privilege escalation alerts
            """)
        
        with col2:
            st.markdown("""
            #### 🛡️ MITRE ATT&CK
            - Tactic identification
            - Technique mapping
            - Severity assessment
            - Countermeasure guidance
            - Threat intelligence
            """)
        
        with col3:
            st.markdown("""
            #### 📈 Analytics
            - Real-time dashboards
            - Threat actor profiling
            - Timeline visualization
            - Risk assessment
            - Executive reporting
            """)
        
        # Quick start instructions
        st.markdown("""
        ---
        ### 🚀 Quick Start
        1. **Upload Data:** Use the sidebar to upload your network flow CSV file
        2. **Configure Analysis:** Adjust threat sensitivity and enable AI analysis
        3. **Generate Insights:** Click analyze to process your security data
        4. **Review Results:** Examine threats, actors, and recommendations
        
        *Or click "Analyze Sample Data" to see a demonstration with simulated network traffic.*
        """)

if __name__ == "__main__":
    main()