import streamlit as st
import re
import json
import pandas as pd
from extractors.general_log_extractor import LogExtractor
from analyzers.general_log_analyzer import LogAnalyzer
from analyzers.panic_log_analyzer import LogPanicDetector

def initialize_log_analyzer_session_state():
    """Initializes session state for the log analyzer if not already present."""
    print("initialize_log_analyzer_session_state() called")
    if 'log_analyzer_analysis' not in st.session_state:
        st.session_state.log_analyzer_analysis = None
    if 'log_analyzer_detected_pods' not in st.session_state:
        st.session_state.log_analyzer_detected_pods = []
    if 'log_analyzer_cluster_id' not in st.session_state:
        st.session_state.log_analyzer_cluster_id = ""

def reset_log_analyzer_state():
    """Resets the state for the log analyzer."""
    print("reset_log_analyzer_state() called")
    st.session_state.log_analyzer_analysis = None
    st.session_state.log_analyzer_detected_pods = []
    st.session_state.log_analyzer_cluster_id = ""

def handle_get_pods():
    """Callback function to handle fetching pods."""
    print("handle_get_pods() called")
    cluster_id = st.session_state.get("log_analyzer_cluster_id_input", "")
    
    # Validate cluster ID
    if not cluster_id or not re.match(r'^[a-f0-9\-]{36}$', cluster_id, re.I):
        st.error("Please enter a valid Cluster ID.")
        st.session_state.log_analyzer_detected_pods = []
        return
    
    # Reset pod list and analysis if cluster ID changed
    if cluster_id != st.session_state.get("log_analyzer_cluster_id", ""):
        st.session_state.log_analyzer_detected_pods = []
        st.session_state.log_analyzer_analysis = None
        
    st.session_state.log_analyzer_cluster_id = cluster_id
    
    log_extractor = LogExtractor()
    with st.spinner(text="Connecting to cluster and fetching pod names..."):
        try:
            detected_pods = log_extractor.auto_detect_pod_names(cluster_id) 
            st.session_state.log_analyzer_detected_pods = detected_pods
            if not detected_pods:
                st.warning("No pods were found for this cluster.")
        except Exception as e:
            st.error(f"Failed to get pods: {e}")
            st.session_state.log_analyzer_detected_pods = []

def render_log_analyzer_ui():
    """Renders the smart log analyzer interface."""
    print("render_log_analyzer_ui() called")
    st.header("📊 Log Analyzer")
    st.markdown("Analyze Weaviate logs for errors, warnings, and insights")

    initialize_log_analyzer_session_state()

    log_extractor = LogExtractor()
    log_analyzer = LogAnalyzer()

    # --- UI for Input Selection ---
    input_method = st.radio(
        "Input Method:",
        ["Manual (Upload File)", "Cluster ID"],
        key="log_input_method",
        horizontal=True
    )

    log_text = None
    analyze_btn = False

    if input_method == "Manual (Upload File)":
        uploaded_file = st.file_uploader(
            "Upload log file (JSON lines, .txt only):",
            type=["txt"],
            accept_multiple_files=False
        )
        if uploaded_file:
            log_text = uploaded_file.read().decode("utf-8")
        
        col1, col2, _ = st.columns([1, 1, 4])
        with col1:
            analyze_btn = st.button("Analyze Logs", type="primary", key="log_analyze_manual", use_container_width=True)
        with col2:
            st.button("Reset", on_click=reset_log_analyzer_state, key="reset_manual", type="secondary", use_container_width=True)

    elif input_method == "Cluster ID":
        st.text_input(
            "Cluster ID:",
            placeholder="e.g., 819dbe5b-8434-4de5-8a17-6a699fb7146d",
            key="log_analyzer_cluster_id_input"
        )

        col1, col2, _ = st.columns([1, 1, 4])
        with col1:
            st.button("Get Pods in Cluster", on_click=handle_get_pods, key="get_pods_btn_log", type="primary", use_container_width=True)
        with col2:
            st.button("Reset", on_click=reset_log_analyzer_state, key="reset_cluster", type="secondary", use_container_width=True)

        if st.session_state.log_analyzer_detected_pods:
            cluster_id = st.session_state.log_analyzer_cluster_id
            st.success(f"Found {len(st.session_state.log_analyzer_detected_pods)} pods for Cluster ID: {cluster_id}")
            
            c1, c2, c3 = st.columns(3)
            with c1:
                pod_options = ["All Pods"] + st.session_state.log_analyzer_detected_pods
                st.selectbox("Select Pod:", pod_options, key="log_analyzer_pod_name")
            with c2:
                st.number_input("Days of logs:", min_value=1, max_value=7, value=1, key="log_analyzer_days")
            with c3:
                st.radio("Log Type:", ["Current", "Previous", "Both"], index=2, key="log_analyzer_log_type", horizontal=True)

            analyze_btn = st.button("Analyze Logs", type="primary", key="log_analyze_cluster", use_container_width=True)

    # --- Logic for Analysis ---
    if analyze_btn:
        st.session_state.log_analyzer_analysis = None
        pod_name = st.session_state.get("log_analyzer_pod_name", "All Pods")
        days = st.session_state.get("log_analyzer_days", 3)
        selected_log_type = st.session_state.get("log_analyzer_log_type", "Both")
        cluster_id = st.session_state.get("log_analyzer_cluster_id", "")

        with st.spinner("Extracting logs..."):
            try:
                pod_logs = {}
                if input_method == "Cluster ID":
                    if not cluster_id:
                        st.error("Missing Cluster ID.")
                        st.stop()

                    selected_pod = None if pod_name == "All Pods" else pod_name
                    
                    log_types_to_fetch = []
                    if selected_log_type in ["Current", "Both"]:
                        log_types_to_fetch.append({"type": "Current", "previous_flag": False})
                    if selected_log_type in ["Previous", "Both"]:
                        log_types_to_fetch.append({"type": "Previous", "previous_flag": True})

                    for log_fetch_info in log_types_to_fetch:
                        log_type_name = log_fetch_info["type"]
                        is_previous = log_fetch_info["previous_flag"]
                        st.info(f"Extracting {log_type_name.lower()} logs from cluster {cluster_id} for the last {days} day(s)...")
                        
                        extracted_logs = log_extractor.extract_logs_from_cluster_analysis(
                            cluster_id, days, pod_name=selected_pod, previous=is_previous
                        )
                        
                        log_type_label = '🟢 Current' if not is_previous else '🔄 Previous'
                        for pod, logs in extracted_logs.items():
                            pod_logs.setdefault(pod, []).append({'log_type': log_type_label, 'logs': logs})

                    if not pod_logs:
                        st.warning("No logs found in cluster.")
                        st.stop()
                else:  # Manual
                    if not log_text:
                        st.error("Please upload a log file.")
                        st.stop()
                    manual_logs = log_extractor.extract_from_text_analysis(log_text)
                    for pod, logs in manual_logs.items():
                        pod_logs.setdefault(pod, []).append({'log_type': '🟢 Current', 'logs': logs})

                total_entries = sum(len(log_set['logs'].splitlines()) for pod_data in pod_logs.values() for log_set in pod_data)
                st.success(f"Extracted {total_entries} log entries from {len(pod_logs)} pod(s).")

            except Exception as e:
                st.error(f"Failed to extract logs: {str(e)}")
                st.stop()
        
        with st.spinner("Analyzing logs..."):
            try:
                for pod_name_key, log_sets in pod_logs.items():
                    for log_set in log_sets:
                        log_text_content = log_set['logs']
                        log_type_label = log_set['log_type']
                        log_analyzer.analyze_logs(log_text_content, pod_name_key, log_type=log_type_label)
                
                analysis = log_analyzer.generate_analysis()
                st.session_state.log_analyzer_analysis = analysis
            except Exception as e:
                st.error(f"Failed to analyze logs: {str(e)}")
                st.stop()
    
    if st.session_state.log_analyzer_analysis:
        display_log_analysis_results(st.session_state.log_analyzer_analysis)

def display_log_analysis_results(analysis):
    """Displays the results of the log analysis."""
    print("display_log_analysis_results() called")
    st.markdown("---")
    st.subheader(f"📈 Analysis Results")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Pods", analysis['total_pods'])
    with col2:
        st.metric("Total Log Entries", analysis['global_stats']['total_logs'])
    with col3:
        error_count = analysis['global_stats']['level_distribution'].get('error', 0)
        st.metric("Error Count", error_count, delta_color="inverse" if error_count > 0 else "normal")
    
    pod_names = list(analysis['pod_summaries'].keys())
    selected_pod = st.selectbox("Select pod to analyze:", pod_names, key="selected_pod_log_analysis")
    
    if selected_pod:
        pod_analysis = analysis['pod_summaries'][selected_pod]
        
        st.markdown("---")
        st.subheader(f"Pod Analysis: {selected_pod}")
        
        if pod_analysis['metadata'].get('weaviate_version'):
            st.info(f"Weaviate Version: {pod_analysis['metadata']['weaviate_version']}")
        
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Total Logs", pod_analysis['total_logs'])
        with c2:
            st.metric("Info", pod_analysis['counts'].get('info', 0))
        with c3:
            st.metric("Warnings", pod_analysis['counts'].get('warning', 0))
        with c4:
            st.metric("Errors", pod_analysis['counts'].get('error', 0))
        
        tabs = st.tabs(["🔴 Errors", "⚠️ Warnings", "ℹ️ Info", "🗂️ Collections/Classes/Tenants"])
        
        with tabs[0]:
            display_log_summaries(pod_analysis['summaries']['error'], "error")
        with tabs[1]:
            display_log_summaries(pod_analysis['summaries']['warning'], "warning")
        with tabs[2]:
            display_log_summaries(pod_analysis['summaries']['info'], "info")
        with tabs[3]:
            if 'collections_classes_tenants' in st.session_state.log_analyzer_analysis:
                display_entity_analysis_summary(st.session_state.log_analyzer_analysis['collections_classes_tenants'])
            else:
                st.info("No collection/class/tenant data found.")
        
        display_panic_detection(pod_analysis, selected_pod)

def display_log_summaries(summaries, level):
    """Displays log summaries in a table format."""
    print("display_log_summaries() called")
    if not summaries:
        st.info(f"No {level} logs found.")
        return
    
    current_summaries = [s for s in summaries if s.log_type == '🟢 Current']
    previous_summaries = [s for s in summaries if s.log_type == '🔄 Previous']

    def render_table(summaries_list, label):
        if not summaries_list:
            st.info(f"No {level} logs found for {label} logs.")
            return
        
        seen = set()
        data = []
        for summary in summaries_list:
            if summary.message not in seen:
                seen.add(summary.message)
                metadata_display = " | ".join([f"{k}: {v}" for k, v in summary.metadata_keys.items()]) if summary.metadata_keys else "None"
                data.append({
                    "Count": summary.count,
                    "Message": summary.message,
                    "First Time": summary.first_timestamp,
                    "Latest Time": summary.latest_timestamp if summary.first_timestamp != summary.latest_timestamp else "Same",
                    "JSON Fields": metadata_display
                })
        
        if data:
            st.markdown(f"### {label} Logs")
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True, hide_index=True)
            if summaries_list:
                with st.expander("📋 Sample Raw Log (from most recent occurrence)"):
                    st.code(summaries_list[0].sample_raw, language='json')

    render_table(current_summaries, '🟢 Current')
    render_table(previous_summaries, '🔄 Previous')

def display_entity_analysis_summary(data):
    print("display_entity_analysis_summary() called")
    """Displays a summary of entity analysis with detailed tables."""
    st.markdown("---")
    st.subheader("📊 Entity Analysis Summary")
    
    total_collections = len(data.get('collections', []))
    total_classes = len(data.get('classes', []))
    total_tenants = len(data.get('tenants', []))
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Collections Found", total_collections)
    with col2:
        st.metric("Classes Found", total_classes)
    with col3:
        st.metric("Tenants Found", total_tenants)

    def format_log_entry(log_entry):
        """Format a log entry for display"""
        # Try to parse JSON from raw log
        try:
            if log_entry.raw_log and log_entry.raw_log.strip().startswith('{'):
                log_json = json.loads(log_entry.raw_log)
                return {
                    "message": log_entry.message,
                    "json": json.dumps(log_json, indent=2)
                }
        except:
            pass
        return {
            "message": log_entry.message,
            "json": log_entry.raw_log if log_entry.raw_log else "No JSON data"
        }

    # Display Collections
    if data.get('collections'):
        st.markdown("### 📁 Collections")
        collections_data = []
        for collection in data['collections']:
            # Get unique logs by message
            unique_logs = {}
            for log in collection.log_entries:
                if log.message not in unique_logs:
                    unique_logs[log.message] = {
                        "entry": log,
                        "count": 1
                    }
                else:
                    unique_logs[log.message]["count"] += 1
            
            # Add each unique log as a separate row
            for log_info in unique_logs.values():
                log = log_info["entry"]
                log_details = format_log_entry(log)
                collections_data.append({
                    "Name": collection.entity_name,
                    "Message": log_details["message"],
                    "JSON": log_details["json"],
                    "First Seen": collection.first_timestamp,
                    "Last Seen": collection.latest_timestamp,
                    "Log Level": log.level,
                    "Count": log_info["count"]
                })
        
        df_collections = pd.DataFrame(collections_data)
        st.dataframe(df_collections, use_container_width=True, hide_index=True)

    # Display Classes
    if data.get('classes'):
        st.markdown("### 🔷 Classes")
        classes_data = []
        for class_info in data['classes']:
            unique_logs = {}
            for log in class_info.log_entries:
                if log.message not in unique_logs:
                    unique_logs[log.message] = {
                        "entry": log,
                        "count": 1
                    }
                else:
                    unique_logs[log.message]["count"] += 1
            
            for log_info in unique_logs.values():
                log = log_info["entry"]
                log_details = format_log_entry(log)
                classes_data.append({
                    "Name": class_info.entity_name,
                    "Message": log_details["message"],
                    "JSON": log_details["json"],
                    "First Seen": class_info.first_timestamp,
                    "Last Seen": class_info.latest_timestamp,
                    "Log Level": log.level,
                    "Count": log_info["count"]
                })
        
        df_classes = pd.DataFrame(classes_data)
        st.dataframe(df_classes, use_container_width=True, hide_index=True)

    # Display Tenants
    if data.get('tenants'):
        st.markdown("### � Tenants")
        tenants_data = []
        for tenant in data['tenants']:
            unique_logs = {}
            for log in tenant.log_entries:
                if log.message not in unique_logs:
                    unique_logs[log.message] = {
                        "entry": log,
                        "count": 1
                    }
                else:
                    unique_logs[log.message]["count"] += 1
            
            for log_info in unique_logs.values():
                log = log_info["entry"]
                log_details = format_log_entry(log)
                tenants_data.append({
                    "Name": tenant.entity_name,
                    "Message": log_details["message"],
                    "JSON": log_details["json"],
                    "First Seen": tenant.first_timestamp,
                    "Last Seen": tenant.latest_timestamp,
                    "Log Level": log.level,
                    "Count": log_info["count"]
                })
        
        df_tenants = pd.DataFrame(tenants_data)
        st.dataframe(df_tenants, use_container_width=True, hide_index=True)

def display_panic_detection(pod_analysis, pod_name):
    """Checks for and displays any panics found in the logs."""
    print("display_panic_detection() called")
    panic_detector = LogPanicDetector()
    panics = panic_detector.detect_panics_in_pod_analysis(pod_analysis)
    
    if panics:
        st.markdown("---")
        st.subheader(f"🚨 Found {len(panics)} Panic(s) in {pod_name}")
        for i, panic in enumerate(panics, 1):
            with st.expander(f"🔥 Panic #{i} - View Stack Trace"):
                st.code(panic, language='text')
