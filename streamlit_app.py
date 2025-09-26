import streamlit as st
from UI.general_log_ui import render_log_analyzer_ui
from UI.panic_log_ui import render_panic_analyzer_ui
from UI.configuration_ui import render_configuration_analyzer_ui
from UI.requests_ui import render_requests_analyzer_ui

st.set_page_config(page_title="Weaviate Analysis Suite", page_icon="🔍", layout="wide")

def main():
    """Main application"""
    st.title("🔍 Weaviate Support Tool")
    
    # Main navigation
    analysis_mode = st.selectbox(
        "Choose Analysis Mode:",
        ["🚨 Panic Analyzer", "📊 Log Analyzer", "🔧 Pod Configuration Analyzer", "🌐 Requests Analyzer"],
        key="analysis_mode"
    )
    
    st.markdown("---")
    
    if analysis_mode == "🚨 Panic Analyzer":
        render_panic_analyzer_ui()
    elif analysis_mode == "🔧 Pod Configuration Analyzer":
        render_configuration_analyzer_ui()
    elif analysis_mode == "🌐 Requests Analyzer":
        render_requests_analyzer_ui()
    else:
        render_log_analyzer_ui()

if __name__ == "__main__":
    main()
