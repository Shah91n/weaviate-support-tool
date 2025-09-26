import streamlit as st
import re
from extractors.panic_log_extractor import PanicLogExtractor
from analyzers.panic_log_analyzer import PanicParser, PanicAnalyzer
from github_client import GitHubClient
import config

def initialize_panic_analyzer_session_state():
    """Initialize session state for panic analyzer"""
    print("initialize_panic_analyzer_session_state() called")
    if 'panics' not in st.session_state:
        st.session_state.panics = []
    if 'selected_panic' not in st.session_state:
        st.session_state.selected_panic = None
    if 'panic_analyzer_cluster_id' not in st.session_state:
        st.session_state.panic_analyzer_cluster_id = ""
    if 'panic_analyzer_pods' not in st.session_state:
        st.session_state.panic_analyzer_pods = []
    if 'panic_analyzer_pod_name' not in st.session_state:
        st.session_state.panic_analyzer_pod_name = "All Pods"

def reset_panic_analyzer_state():
    """Reset session state for panic analyzer"""
    print("reset_panic_analyzer_state() called")
    st.session_state.panics = []
    st.session_state.selected_panic = None
    st.session_state.panic_analyzer_pods = []
    st.session_state.panic_analyzer_pod_name = "All Pods"

def handle_get_panic_pods():
    """Callback function to handle fetching pods for panic analysis"""
    print("handle_get_panic_pods() called")
    cluster_id = st.session_state.get("panic_analyzer_cluster_id_input", "")
    
    # Validate cluster ID
    if not cluster_id or not re.match(r'^[a-f0-9\-]{36}$', cluster_id, re.I):
        st.error("Please enter a valid Cluster ID.")
        st.session_state.panic_analyzer_pods = []
        return
    
    # Reset pod list if cluster ID changed
    if cluster_id != st.session_state.get("panic_analyzer_cluster_id", ""):
        st.session_state.panic_analyzer_pods = []
        
    st.session_state.panic_analyzer_cluster_id = cluster_id
    
    log_extractor = PanicLogExtractor()
    with st.spinner(text="Connecting to cluster and fetching pod names..."):
        try:
            detected_pods = log_extractor.auto_detect_pod_names(cluster_id)
            st.session_state.panic_analyzer_pods = detected_pods
            if not detected_pods:
                st.warning("No pods were found for this cluster.")
        except Exception as e:
            st.error(f"Failed to get pods: {e}")
            st.session_state.panic_analyzer_pods = []

def render_panic_analyzer_ui():
    """Render the panic analyzer interface"""
    print("render_panic_analyzer_ui() called")
    st.header("🚨 Panic Analyzer")
    st.markdown("Analyze Go panic stack traces")

    # Initialize components
    initialize_panic_analyzer_session_state()
    log_extractor = PanicLogExtractor()
    panic_parser = PanicParser()
    github_client = GitHubClient(token=config.GITHUB_TOKEN)
    analyzer = PanicAnalyzer()
    
    # Input section
    analyze_btn = False
    input_method = st.radio(
        "Input Method:",
        ["Manual (Paste Stack)", "Cluster ID"],
        key="panic_input_method",
        horizontal=True
    )

    if input_method == "Manual (Paste Stack)": # Manual input
        panic_text = st.text_area(
            "Paste panic stack trace here:",
            height=300,
            placeholder="panic: runtime error: ..."
        )
        
        col1, col2, _ = st.columns([1, 1, 4])
        with col1:
            if panic_text:
                analyze_btn = st.button("🔍 Analyze Stack Trace", type="primary", use_container_width=True)
            else:
                st.button("🔍 Analyze Stack Trace", type="primary", use_container_width=True, disabled=True)
        with col2:
            st.button("Reset", on_click=reset_panic_analyzer_state, key="reset_manual", type="secondary", use_container_width=True)

    else:  # Cluster ID
        st.text_input(
            "Cluster ID:",
            placeholder="e.g., 819dbe5b-8434-4de5-8a17-6a699fb7146d",
            key="panic_analyzer_cluster_id_input"
        )

        col1, col2, _ = st.columns([1, 1, 4])
        with col1:
            st.button("Get Pods", on_click=handle_get_panic_pods, key="get_pods_btn_panic", type="primary", use_container_width=True)
        with col2:
            st.button("Reset", on_click=reset_panic_analyzer_state, key="reset_cluster", type="secondary", use_container_width=True)

        if st.session_state.panic_analyzer_pods:
            cluster_id = st.session_state.panic_analyzer_cluster_id
            st.success(f"Found {len(st.session_state.panic_analyzer_pods)} pods for Cluster ID: {cluster_id}")
            
            c1, c2, c3 = st.columns(3)
            with c1:
                pod_options = ["All Pods"] + st.session_state.panic_analyzer_pods
                st.selectbox("Select Pod:", pod_options, key="panic_analyzer_pod_name")
            with c2:
                st.number_input("Days of logs:", min_value=1, max_value=7, value=1, key="panic_analyzer_days")
            with c3:
                st.radio("Log Type:", ["Current", "Previous", "Both"], index=2, key="panic_analyzer_log_type", horizontal=True)

            analyze_btn = st.button("Analyze Logs", type="primary", use_container_width=True)
        
    if analyze_btn:
        st.session_state.panics = []
        st.session_state.selected_panic = None
        
        raw_panics = []
        error = None
        
        # Extract panics
        with st.spinner("Extracting panic information..."):
            try:
                if input_method == "Cluster ID":
                    cluster_id = st.session_state.get("panic_analyzer_cluster_id_input", "")
                    if not cluster_id or not re.match(r'^[a-f0-9\-]{36}$', cluster_id, re.I):
                        error = "Invalid or missing Cluster ID"
                    else:
                        st.info(f"Connecting to cluster {cluster_id}...")
                        
                        # Get selected pod and log type
                        selected_pod = st.session_state.get("panic_analyzer_pod_name", "All Pods")
                        log_type = st.session_state.get("panic_analyzer_log_type", "Both")
                        
                        # Extract panics based on selection
                        days = st.session_state.get("panic_analyzer_days", 1)
                        pod_panics = log_extractor.extract_panics_from_cluster(
                            cluster_id,
                            pod_name=None if selected_pod == "All Pods" else selected_pod,
                            days=days,
                            include_current="Current" in log_type or "Both" in log_type,
                            include_previous="Previous" in log_type or "Both" in log_type
                        )
                        
                        if not pod_panics:
                            st.info("No panics found in cluster logs")
                        else:
                            for pod, panics in pod_panics.items():
                                for panic in panics:
                                    raw_panics.append((panic, pod))
                            st.success(f"Found {len(raw_panics)} panic(s)")
                else:
                    if not panic_text:
                        error = "Please paste a panic stack trace"
                    else:
                        extracted = log_extractor.extract_from_text(panic_text)
                        if not extracted:
                            error = "No valid panic found in input"
                        else:
                            raw_panics = [(panic, None) for panic in extracted]
                            st.success(f"Found {len(raw_panics)} panic(s)")
                            
            except Exception as e:
                error = f"Failed: {str(e)}"
        
        if error:
            st.error(error)
            st.stop()
        
        # Parse panics
        if raw_panics:
            parsed = []
            for raw, pod in raw_panics:
                panic_info = panic_parser.parse_panic(raw, pod)
                if panic_info:
                    parsed.append(panic_info)
            
            if parsed:
                unique = panic_parser.deduplicate_panics(parsed)
                st.session_state.panics = unique
            else:
                st.error("Failed to parse panic information")
    
    # Display results
    if st.session_state.panics:
        st.markdown("---")
        st.subheader(f"📊 Found {len(st.session_state.panics)} Unique Panic(s)")
        
        # Select panic
        options = []
        for panic, count in st.session_state.panics:
            label = f"{panic.file_path.split('/')[-1]}:{panic.line_number} - {panic.panic_type} ({count}x)"
            options.append(label)
        
        selected_idx = st.selectbox(
            "Select panic to analyze:",
            range(len(options)),
            format_func=lambda x: options[x]
        )
        
        if selected_idx is not None:
            selected_panic, count = st.session_state.panics[selected_idx]
            
            # Show metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Occurrences", count)
            with col2:
                st.metric("Type", selected_panic.panic_type)
            with col3:
                if selected_panic.pod_name:
                    st.metric("Pod", selected_panic.pod_name)
            
            # Analyze
            with st.spinner("Fetching code and analyzing..."):
                code_context = github_client.fetch_code_context(
                    selected_panic.file_path,
                    selected_panic.line_number
                )
                analysis = analyzer.analyze(selected_panic, code_context)
            
            # Display analysis
            st.markdown("---")
            st.subheader("🔬 Analysis")
            
            tab1, tab2, tab3 = st.tabs(["Summary", "Code", "Stack Trace"])
            
            with tab1:
                st.markdown(analysis['summary'])
                
                # Show Weaviate version if available
                if selected_panic.weaviate_version:
                    st.info(f"Weaviate Version: {selected_panic.weaviate_version}")
                
                st.markdown("\n**Call chain (in order):**")
                for i, loc in enumerate(analysis['locations_to_check'], 1):
                    st.code(f"{i}. {loc}", language='text')
            
            with tab2:
                # Show code for multiple important locations IN ORDER
                important_files = []
                for loc in analysis['locations_to_check'][:5]:  # Top 5 in call order
                    if '.go:' in loc:
                        match = re.search(r'([^\s]+\.go):(\d+)', loc)
                        if match:
                            file_path = match.group(1)
                            line_num = int(match.group(2))
                            
                            # Skip error wrapper unless it's the only file
                            if 'error_group_wrapper' not in file_path or len(analysis['locations_to_check']) == 1:
                                important_files.append((file_path, line_num))
                
                # Show code for each file IN STACK ORDER
                for idx, (file_path, line_num) in enumerate(important_files[:3]):
                    file_name = file_path.split('/')[-1]
                    call_order = "→ Called by" if idx > 0 else "⚠️ Panic location"
                    st.markdown(f"**{call_order}: {file_name}**")
                    
                    # Generate GitHub URL
                    github_path = github_client.convert_to_github_path(file_path)
                    github_url = f"https://github.com/weaviate/weaviate/blob/main/{github_path}#L{line_num}"
                    
                    st.markdown(f"[View on GitHub]({github_url})")
                    
                    # Fetch and show code
                    ctx = github_client.fetch_code_context(file_path, line_num)
                    if ctx:
                        code_display = []
                        for i, line in enumerate(ctx['lines'], start=ctx['start_line']):
                            if i == line_num:
                                code_display.append(f"{i:4d} >>> {line}  # <-- HERE")
                            else:
                                code_display.append(f"{i:4d}     {line}")
                        st.code('\n'.join(code_display), language='go')
                    else:
                        st.warning(f"Unable to fetch {file_name} from GitHub")
                    
                    if idx < len(important_files) - 1:
                        st.markdown("---")
            
            with tab3:
                st.code('\n'.join(selected_panic.stack_trace), language='text')
            