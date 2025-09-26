import streamlit as st
import re
import pandas as pd
import plotly.graph_objects as go
from analyzers.configuration_analyzer import ConfigurationAnalyzer

def render_configuration_analyzer_ui():
    """Configuration analyzer interface for analyzing kubectl describe pod output"""
    print("render_configuration_analyzer_ui called")
    st.header("🔧 Pod Configuration Analyzer")
    st.markdown("Analyze Weaviate configuration and resource settings")
    
    # Initialize configuration analyzer
    configuration_analyzer = ConfigurationAnalyzer()

    # Input method selection (horizontal radio buttons)
    input_method = st.radio(
        "Choose input method:",
        ["📋 Paste kubectl describe output", "☁️ Connect to cluster"],
        key="configuration_input_method",
        horizontal=True
    )
    
    # Input fields (vertical layout)
    if input_method == "☁️ Connect to cluster":
        cluster_id = st.text_input("Cluster ID:", key="configuration_cluster_id")
        col1, col2 = st.columns([1, 1])
        with col1:
            analyze_btn = st.button("🔍 List Weaviate Pods", key="list_pods", use_container_width=True)
        with col2:
            if st.button("🗑️ Reset", key="reset_config", use_container_width=True):
                # Clear session state and rerun
                for key in ["pods", "configuration_info"]:
                    if key in st.session_state:
                        del st.session_state[key]
                st.rerun()
    
    # Input area for manual input
    if input_method == "📋 Paste kubectl describe output":
        describe_text = st.text_area(
            "Paste kubectl describe pod output:",
            height=200,
            placeholder="kubectl describe pod weaviate-0\n\nName: weaviate-0\nNamespace: ...",
            key="configuration_describe_text"
        )
    
    # Analysis section
    if input_method == "☁️ Connect to cluster":
        # REMOVED THE DUPLICATE BUTTON - Use the analyze_btn from above
        if analyze_btn:  # This refers to the button created in the col1, col2 section above
            if not cluster_id:
                st.error("Please enter a cluster ID")
                st.stop()
            
            try:
                with st.spinner("Connecting to cluster and finding Weaviate pods..."):
                    st.info(f"Connecting to cluster {cluster_id}...")
                    configuration_analyzer.extractor.connect_to_cluster(cluster_id)
                    pods = configuration_analyzer.extractor.get_pod_details()

                    if not pods:
                        st.error("No Weaviate pods found in cluster")
                        st.stop()
                    
                    # Store pods in session state
                    st.session_state['pods'] = pods
                    st.success(f"✅ Found {len(pods)} Weaviate pod(s)")
                    
            except Exception as e:
                st.error(f"Failed: {str(e)}")
                st.stop()
        
        # Show pod selection if we have pods
        if 'pods' in st.session_state and st.session_state['pods']:
            st.markdown("---")
            st.subheader("🔍 Select Pod to Analyze")
            
            # Create pod table
            pod_data = []
            for pod in st.session_state['pods']:
                pod_data.append([
                    pod['name'],
                    pod['status'],
                    pod['cpu_request'],
                    pod['cpu_limit'],
                    pod['memory_request'],
                    pod['memory_limit']
                ])
            
            # Show pod info in a table
            pod_df = pd.DataFrame(
                pod_data,
                columns=['Pod Name', 'Status', 'CPU Request', 'CPU Limit', 'Memory Request', 'Memory Limit']
            )
            st.dataframe(pod_df, hide_index=True, use_container_width=True)
            
            # Pod selection dropdown
            selected_pod = st.selectbox(
                "Select pod to analyze:",
                [pod['name'] for pod in st.session_state['pods']],
                format_func=lambda x: f"{x} ({next(p['status'] for p in st.session_state['pods'] if p['name'] == x)})"
            )
            
            col1, col2 = st.columns([1, 1])
            with col1:
                analyze_config_btn = st.button("🔍 Analyze Configuration", key="analyze_config", use_container_width=True)
            with col2:
                if st.button("🗑️ Reset", key="reset_pod", use_container_width=True):
                    for key in ["pods", "configuration_info"]:
                        if key in st.session_state:
                            del st.session_state[key]
                    st.rerun()
            
            if analyze_config_btn:
                try:
                    with st.spinner(f"Analyzing configuration for {selected_pod}..."):
                        config_info = configuration_analyzer.analyze_from_cluster(cluster_id, selected_pod)

                        if config_info:
                            st.session_state['configuration_info'] = config_info
                            st.success(f"✅ Successfully analyzed {selected_pod}")
                        else:
                            st.error("No Weaviate Configuration found in describe output")
                            st.stop()
                except Exception as e:
                    st.error(f"Failed: {str(e)}")
                    st.stop()

    else:  # Manual mode
        col1, col2 = st.columns([1, 1])
        with col1:
            analyze_btn = st.button("🔍 Analyze Configuration", use_container_width=True)
        with col2:
            if st.button("🗑️ Reset", key="reset_manual", use_container_width=True):
                if 'configuration_info' in st.session_state:
                    del st.session_state['configuration_info']
                st.rerun()
        
        if analyze_btn:
            if not describe_text.strip():
                st.error("Please paste kubectl describe pod output")
                st.stop()
            
            try:
                with st.spinner("Analyzing configuration..."):
                    config_info = configuration_analyzer.analyze_from_text(describe_text)

                    if config_info:
                        st.session_state['configuration_info'] = config_info
                        st.success("✅ Successfully analyzed configuration")
                    else:
                        st.error("No Weaviate Configuration found in describe output")
                        st.stop()
            except Exception as e:
                st.error(f"Failed: {str(e)}")
                st.stop()
    
    # Display results if we have them in session state
    if 'configuration_info' in st.session_state:
        display_configuration_analysis(st.session_state['configuration_info'], configuration_analyzer)

def display_configuration_analysis(configuration_info, configuration_analyzer):
    """Display configuration analysis results with proper section organization"""
    print("display_configuration_analysis called")
    st.markdown("---")
    
    # ===== SECTION 1: ESSENTIAL CONFIGURATION =====
    st.subheader("⚡ Essential Configuration")

    essential_df = configuration_analyzer.create_essential_dataframe(configuration_info)
    st.dataframe(essential_df, hide_index=True, use_container_width=True)
    
    # Show all environment variables in expander
    basic_df, env_df = configuration_analyzer.create_summary_dataframe(configuration_info)
    with st.expander(f"📋 All Environment Variables ({len(env_df)} total)"):
        st.dataframe(env_df, hide_index=True, use_container_width=True)
    
    # ===== SECTION 2: MEMORY CONFIGURATION ANALYSIS =====
    st.markdown("---")
    st.subheader("🧠 Memory Configuration Analysis")
    
    # Memory analysis
    memory_analysis = configuration_analyzer.analyze_memory_configuration(configuration_info)

    # Status indicator
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if memory_analysis.recommendation == "OPTIMAL RANGE":
            st.success(f"✅ {memory_analysis.recommendation}")
        elif "INCREASE" in memory_analysis.recommendation:
            st.warning(f"⚠️ {memory_analysis.recommendation}")
        else:
            st.error(f"❌ {memory_analysis.recommendation}")
    
    with col2:
        # Memory metrics with both GiB and GB
        gomemlimit_gb = memory_analysis.gomemlimit_gib * 1.073741824  # GiB to GB conversion
        st.metric(
            "Current GOMEMLIMIT", 
            f"{memory_analysis.gomemlimit_gib:.1f} GiB ({gomemlimit_gb:.1f} GB)",
            f"{memory_analysis.current_ratio:.1f}% of limit"
        )
    
    # Detailed memory analysis
    with st.expander("📊 Detailed Memory Analysis", expanded=True):
        st.markdown(f"```\n{memory_analysis.analysis}\n```")
        
        # Visual representation
        fig = go.Figure()
        
        # Current configuration
        fig.add_trace(go.Bar(
            name="Current Setup",
            x=["Memory Limit", "GOMEMLIMIT", "OS Cache"],
            y=[
                memory_analysis.memory_limit_gib,
                memory_analysis.gomemlimit_gib,
                memory_analysis.memory_limit_gib - memory_analysis.gomemlimit_gib
            ],
            marker_color=["lightblue", "orange", "lightgreen"]
        ))
        
        # Recommended configuration
        fig.add_trace(go.Bar(
            name="Recommended Setup",
            x=["Memory Limit", "Recommended GOMEMLIMIT", "OS Cache"],
            y=[
                memory_analysis.memory_limit_gib,
                memory_analysis.recommended_gomemlimit_gib,
                memory_analysis.memory_limit_gib - memory_analysis.recommended_gomemlimit_gib
            ],
            marker_color=["lightblue", "red", "lightgreen"]
        ))
        
        fig.update_layout(
            title="Memory Allocation Comparison",
            yaxis_title="Memory (GiB)",
            barmode='group',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Recommendation metrics with both GiB and GB
        col1, col2 = st.columns(2)
        
        with col1:
            recommended_gb = memory_analysis.recommended_gomemlimit_gib * 1.073741824
            st.metric(
                "Recommended GOMEMLIMIT", 
                f"{memory_analysis.recommended_gomemlimit_gib:.0f} GiB ({recommended_gb:.0f} GB)",
                f"{memory_analysis.recommended_ratio:.0f}% of limit"
            )
        
        with col2:
            os_cache_gib = memory_analysis.memory_limit_gib - memory_analysis.recommended_gomemlimit_gib
            os_cache_gb = os_cache_gib * 1.073741824
            st.metric(
                "OS Cache Available",
                f"{os_cache_gib:.0f} GiB ({os_cache_gb:.0f} GB)",
                "For disk I/O caching"
            )
