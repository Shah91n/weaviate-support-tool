import streamlit as st
import re
import pandas as pd
from analyzers.requests_analyzer import RequestsAnalyzer


def render_requests_analyzer_ui():
    """Requests analyzer interface for analyzing istio-proxy request logs"""
    print("render_requests_analyzer_ui called")
    st.header("Requests Analyzer")
    st.markdown("Analyze Weaviate requests from istio-proxy logs - track POST, DELETE, Batching, Queries, and operations across all pods (configurable days, max 7)")
    
    requests_analyzer = RequestsAnalyzer()
    
    # Initialize session state
    if 'requests_pod_analyses' not in st.session_state:
        st.session_state.requests_pod_analyses = None
    
    # Input section
    col1, col2 = st.columns([3, 1])
    
    with col1:
        cluster_id = st.text_input(
            "Cluster ID:",
            placeholder="e.g., 819dbe5b-8434-4de5-8a17-6a699fb7146d",
            key="requests_cluster_id"
        )
    
    with col2:
        days = st.number_input(
            "Days of requests:",
            min_value=1,
            max_value=7,
            value=3,
            help="Maximum 7 days of request history"
        )
    
    # Buttons
    col1, col2 = st.columns([1, 1])
    with col1:
        analyze_btn = st.button("Analyze All Pods", type="primary", use_container_width=True, key="requests_analyze")
    with col2:
        clear_btn = st.button("Clear", use_container_width=True, key="requests_clear")
    
    if clear_btn:
        _clear_session_state()
    
    if analyze_btn:
        if not cluster_id or not re.match(r'^[a-f0-9\-]{36}$', cluster_id, re.I):
            st.error("Please enter a valid cluster ID")
            st.stop()
        
        st.session_state.requests_pod_analyses = None
        
        # Analyze requests from all pods in cluster
        with st.spinner(f"Connecting to cluster and analyzing istio-proxy logs from all Weaviate pods (up to {days} days of history, or less for recently created/restarted pods)..."):
            try:
                st.info(f"Connecting to cluster {cluster_id} and fetching {days} days of request logs...")
                pod_analyses = requests_analyzer.analyze_from_cluster(cluster_id, days)
                
                if pod_analyses:
                    st.session_state.requests_pod_analyses = pod_analyses
                    total_requests = sum(analysis.total_requests for analysis in pod_analyses.values())
                    provider = getattr(requests_analyzer, 'cloud_provider', 'Unknown')
                    provider_text = f" (hosted on {provider})" if provider != 'Unknown' else ""
                    st.success(f"Analyzed {len(pod_analyses)} pod(s) with {total_requests} total requests{provider_text}")
                else:
                    st.warning("No requests found in any pod logs. This could be due to a recent restarted pod(s) and no requests logged yet. The analyzer looks for HTTP requests (e.g., GET, POST, PUT, DELETE) from the istio-proxy sidecar logs.")
                    st.stop()

            except Exception as e:
                st.error(f"Failed to analyze requests: {str(e)}")
                st.stop()
    
    # Display results
    if st.session_state.requests_pod_analyses:
        display_multi_pod_requests_analysis(st.session_state.requests_pod_analyses, requests_analyzer, days)

def display_multi_pod_requests_analysis(pod_analyses, requests_analyzer, days):
    """Display requests analysis results for multiple pods"""
    print("display_multi_pod_requests_analysis called") 
    st.markdown("---")
    
    # Global Overview
    st.subheader("Global Requests Overview")
    
    # Show cloud provider if available
    provider = getattr(requests_analyzer, 'cloud_provider', None)
    if provider and provider != "Unknown":
        st.info(f"Cluster hosted on {provider}")
    
    # Show log fetching details if available
    log_details = getattr(requests_analyzer, 'log_fetching_details', None)
    if log_details:
        st.markdown("**Log Fetching Details:**")
        for detail in log_details:
            st.text(detail)
    
    # Calculate global metrics
    total_requests = sum(analysis.total_requests for analysis in pod_analyses.values())
    all_success_requests = sum(analysis.status_codes.get('200', 0) for analysis in pod_analyses.values())
    global_success_rate = (all_success_requests / total_requests) * 100 if total_requests > 0 else 0
    
    # Combine all request types
    global_request_types = {}
    global_collections = {}
    
    for analysis in pod_analyses.values():
        for req_type, count in analysis.request_types.items():
            global_request_types[req_type] = global_request_types.get(req_type, 0) + count
        for collection, count in analysis.collections_accessed.items():
            global_collections[collection] = global_collections.get(collection, 0) + count
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Requests", total_requests)
    
    with col2:
        st.metric("Global Success Rate", f"{global_success_rate:.1f}%")
    
    with col3:
        st.metric("Request Types", len(global_request_types))
    
    with col4:
        collections_count = len(global_collections)
        st.metric("Collections", collections_count if collections_count > 0 else "None detected")
    
    # Global request types breakdown
    st.markdown("#### Global Request Types Distribution")
    global_summary_data = []
    for req_type, count in sorted(global_request_types.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_requests) * 100
        global_summary_data.append({
            'Request Type': req_type,
            'Total Count': count,
            'Percentage': f"{percentage:.1f}%"
        })
    
    global_df = pd.DataFrame(global_summary_data)
    st.dataframe(global_df, hide_index=True, use_container_width=True)
    
    # Per-Pod Analysis
    st.markdown("---")
    st.subheader("Per-Pod Analysis")
    
    # Pod selector
    pod_names = list(pod_analyses.keys())
    selected_pod = st.selectbox(
        "Select pod to analyze in detail:",
        pod_names,
        key="selected_requests_pod"
    )
    
    if selected_pod:
        pod_analysis = pod_analyses[selected_pod]
        
        st.markdown(f"#### Pod Analysis: {selected_pod}")
        
        # Pod-specific metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Requests", pod_analysis.total_requests)
        
        with col2:
            pod_success = pod_analysis.status_codes.get('200', 0)
            pod_success_rate = (pod_success / pod_analysis.total_requests) * 100 if pod_analysis.total_requests > 0 else 0
            st.metric("Success Rate", f"{pod_success_rate:.1f}%")
        
        with col3:
            st.metric("Request Types", len(pod_analysis.request_types))
        
        with col4:
            pod_collections = len(pod_analysis.collections_accessed)
            st.metric("Collections", pod_collections if pod_collections > 0 else "None detected")
        
        # Time range for this pod
        if pod_analysis.time_range[0] != 'Unknown':
            start_time = pod_analysis.time_range[0]
            end_time = pod_analysis.time_range[1]
            st.info(f"Pod Time Range (UTC): {start_time} → {end_time}")
        
        # Detailed Request Logs
        st.markdown("---")
        st.subheader("Detailed Request Logs")
        
        # Filter by HTTP Method instead of Request Type
        method_options = ["All"] + list(pod_analysis.requests_by_method.keys())
        selected_method = st.selectbox(
            "Filter by HTTP Method:",
            method_options,
            key="selected_method"
        )
        
        # Get requests to display
        if selected_method == "All":
            all_requests = []
            for requests_list in pod_analysis.requests_by_method.values():
                all_requests.extend(requests_list)
            display_requests = sorted(all_requests, key=lambda x: x.timestamp, reverse=True)
        else:
            display_requests = sorted(pod_analysis.requests_by_method.get(selected_method, []), 
                                    key=lambda x: x.timestamp, reverse=True)
        
        if display_requests:
            st.info(f"Showing all {len(display_requests)} requests from the last {days} days")
            
            requests_df = requests_analyzer.create_requests_dataframe(display_requests)
            st.dataframe(
                requests_df,
                hide_index=True,
                use_container_width=True,
                column_config={
                    "Time": st.column_config.TextColumn("Time", width="small"),
                    "Method": st.column_config.TextColumn("Method", width="small"),
                    "Request Type": st.column_config.TextColumn("Request Type", width="medium"),
                    "Endpoint": st.column_config.TextColumn("Endpoint", width="large"),
                    "Status": st.column_config.TextColumn("Status", width="small"),
                    "Duration": st.column_config.TextColumn("Duration", width="small"),
                    "Collection": st.column_config.TextColumn("Collection", width="medium"),
                    "Object ID": st.column_config.TextColumn("Object ID", width="medium"),
                    "Source IP": st.column_config.TextColumn("Source IP", width="medium"),
                }
            )
        else:
            st.info("No requests found for the selected filter")
        
        # Display additional pod sections
        _display_pod_additional_sections(pod_analysis, requests_analyzer)


def _display_pod_additional_sections(analysis, requests_analyzer):
    """Display additional sections for pod analysis"""
    print("Displaying additional pod sections")
    # Request Types Breakdown
    st.markdown("---")
    st.markdown("Request Types Breakdown and analysis")

    summary_df = requests_analyzer.create_summary_dataframe(analysis)
    st.dataframe(summary_df, hide_index=True, use_container_width=True)
    
    # Collections & Performance
    if analysis.collections_accessed or analysis.performance_stats:
        st.markdown("---")
        st.subheader("Collections & Performance Details")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if analysis.collections_accessed:
                st.markdown("**Collections Accessed:**")
                collections_data = []
                for collection, count in sorted(analysis.collections_accessed.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / analysis.total_requests) * 100
                    collections_data.append({
                        'Collection': collection,
                        'Requests': count,
                        'Percentage': f"{percentage:.1f}%"
                    })
                
                collections_df = pd.DataFrame(collections_data)
                st.dataframe(collections_df, hide_index=True, use_container_width=True)
        
        with col2:
            if analysis.performance_stats:
                st.markdown("**Performance by Request Type:**")
                perf_data = []
                for req_type, stats in sorted(analysis.performance_stats.items(), key=lambda x: x[1]['avg_ms'], reverse=True):
                    avg_duration = stats['avg_ms']
                    duration_display = _format_duration_display(avg_duration)
                    max_duration = _format_duration_display(stats['max_ms'])
                    
                    perf_data.append({
                        'Request Type': req_type,
                        'Avg Duration': duration_display,
                        'Max Duration': max_duration,
                        'Count': stats['count']
                    })
                
                perf_df = pd.DataFrame(perf_data)
                st.dataframe(perf_df, hide_index=True, use_container_width=True)
    
    # Status Codes
    if len(analysis.status_codes) > 1:
        st.markdown("---")
        st.subheader("Status Codes")
        
        st.markdown("**Status Code Distribution:**")
        status_data = []
        for status, count in sorted(analysis.status_codes.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / analysis.total_requests) * 100
            status_meaning = _get_status_code_meaning(status)
            
            status_data.append({
                'Status': f"{status} ({status_meaning})",
                'Count': count,
                'Percentage': f"{percentage:.1f}%"
            })
        
        status_df = pd.DataFrame(status_data)
        st.dataframe(status_df, hide_index=True, use_container_width=True)
    
    # Error & Warning Requests
    error_warning_requests = []
    
    # Collect all requests for error/warning analysis
    all_requests_for_errors = []
    for requests_list in analysis.requests_by_method.values():
        all_requests_for_errors.extend(requests_list)
    
    # Filter for non-success status codes
    error_warning_requests = [
        req for req in all_requests_for_errors 
        if not req.status_code.startswith('2')  # Not 2xx success codes
    ]
    
    if error_warning_requests:
        st.markdown("---")
        st.subheader("Error & Warning Requests")
        st.markdown("**All requests that returned error or warning status codes:**")
        
        # Sort by timestamp (most recent first)
        error_warning_requests.sort(key=lambda x: x.timestamp, reverse=True)
        
        # Create detailed table for errors/warnings
        error_data = []
        for request in error_warning_requests:
            time_display = request.timestamp
            if 'T' in time_display:
                time_display = time_display.split('T')[1][:8]
            
            duration_display = _format_duration_display(request.duration_ms)
            status_meaning = _get_status_code_meaning(request.status_code)
            
            error_data.append({
                'Time': time_display,
                'Status': f"{request.status_code} ({status_meaning})",
                'Method': request.method,
                'Endpoint': request.endpoint,
                'Duration': duration_display,
                'Collection': request.collection_name or '-',
                'Object ID': request.object_id or '-',
                'Source IP': request.source_ip,
                'Request Type': request.request_type,
                'User Agent': request.user_agent
            })
        
        if error_data:
            error_df = pd.DataFrame(error_data)
            st.dataframe(
                error_df,
                hide_index=True,
                use_container_width=True,
                column_config={
                    "Time": st.column_config.TextColumn("Time", width="small"),
                    "Status": st.column_config.TextColumn("Status", width="medium"),
                    "Method": st.column_config.TextColumn("Method", width="small"),
                    "Endpoint": st.column_config.TextColumn("Endpoint", width="large"),
                    "Duration": st.column_config.TextColumn("Duration", width="small"),
                    "Collection": st.column_config.TextColumn("Collection", width="medium"),
                    "Object ID": st.column_config.TextColumn("Object ID", width="medium"),
                    "Source IP": st.column_config.TextColumn("Source IP", width="medium"),
                    "Request Type": st.column_config.TextColumn("Request Type", width="medium"),
                    "User Agent": st.column_config.TextColumn("User Agent", width="medium"),
                }
            )
            
            st.info(f"Found {len(error_warning_requests)} requests with error/warning status codes")
        else:
            st.success("No error or warning requests found - all requests completed successfully!")
    else:
        st.success("No error or warning requests found - all requests completed successfully!")


def _format_duration_display(duration_ms: float) -> str:
    """Format duration with minutes if over 1000ms"""
    print("Formatting duration display")
    if duration_ms >= 1000:
        minutes = duration_ms / 60000
        if minutes >= 1:
            return f"{minutes:.1f}min"
        else:
            seconds = duration_ms / 1000
            return f"{seconds:.1f}s"
    else:
        return f"{duration_ms:.0f}ms"


def _get_status_code_meaning(status_code: str) -> str:
    """Get short meaning for HTTP status codes"""
    print(f"Getting meaning for status code: {status_code}")
    status_meanings = {
        '200': 'OK',
        '201': 'Created',
        '204': 'No Content',
        '400': 'Bad Request',
        '401': 'Unauthorized',
        '403': 'Forbidden',
        '404': 'Not Found',
        '409': 'Conflict',
        '422': 'Invalid',
        '429': 'Rate Limited',
        '500': 'Server Error',
        '502': 'Bad Gateway',
        '503': 'Unavailable',
        '504': 'Timeout'
    }
    return status_meanings.get(status_code, 'Unknown')


def _clear_session_state():
    """Clear all session state data"""
    print("clear_session_state called")
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.cache_data.clear()
    st.rerun()
