import re
import json
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Any
import pandas as pd
from extractors.requests_extractor import RequestsExtractor


@dataclass
class RequestInfo:
    """Individual request information"""
    timestamp: str
    method: str
    endpoint: str
    status_code: str
    duration_ms: int
    source_ip: str
    user_agent: str
    request_id: str
    collection_name: Optional[str] = None
    object_id: Optional[str] = None
    request_type: str = "Unknown"
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


@dataclass 
class RequestAnalysis:
    """Analysis results for all requests"""
    total_requests: int
    request_types: Dict[str, int]
    collections_accessed: Dict[str, int]
    status_codes: Dict[str, int]
    source_ips: Dict[str, int]
    user_agents: Dict[str, int]
    time_range: Tuple[str, str]
    requests_by_type: Dict[str, List[RequestInfo]]
    requests_by_method: Dict[str, List[RequestInfo]]  # Added for method filtering
    performance_stats: Dict[str, Dict[str, float]]
    summary: str


class RequestsAnalyzer:
    """Analyzer for Weaviate request logs from istio-proxy"""
    
    def __init__(self):
        pass
    
    def analyze_from_cluster(self, cluster_id: str, days: int = 7) -> Optional[Dict[str, RequestAnalysis]]:
        """Analyze requests from all pods in cluster, with cloud provider detection (AWS/GCP)."""
        print(f"Analyzing requests from cluster: {cluster_id} for past {days} days")
        extractor = RequestsExtractor()
        try:
            extractor.connect_to_cluster(cluster_id)

            # Try to list pods; detector will fall back to Unknown provider if needed
            pod_names = extractor.list_weaviate_pods()
            if not pod_names:
                # Try AWS namespace
                pod_names = extractor.list_weaviate_pods(provider='AWS')
            if not pod_names:
                raise Exception("No Weaviate pods found")

            pod_analyses = {}
            log_fetching_details = []
            hours = days * 24

            # Detect provider using a small sample if possible
            provider = 'Unknown'
            sample_pod = pod_names[0] if pod_names else None
            if sample_pod:
                sample_log = extractor.fetch_pod_logs(sample_pod, since_hours=1)
                if sample_log:
                    provider = extractor.detect_cloud_provider(sample_log)

            for pod_name in pod_names:
                try:
                    all_logs = ''
                    current = extractor.fetch_pod_logs(pod_name, since_hours=hours, previous=False)
                    prev = extractor.fetch_pod_logs(pod_name, since_hours=hours, previous=True)
                    if current:
                        all_logs += current + "\n"
                        log_fetching_details.append(f"Got current logs from {pod_name}: {len(current.splitlines())} lines")
                    if prev:
                        all_logs += prev + "\n"
                        log_fetching_details.append(f"Got previous logs from {pod_name}: {len(prev.splitlines())} lines")

                    if all_logs.strip():
                        analysis = self._analyze_from_text(all_logs)
                        if analysis:
                            if not hasattr(analysis, 'cloud_provider'):
                                setattr(analysis, 'cloud_provider', provider)
                            pod_analyses[pod_name] = analysis
                    else:
                        log_fetching_details.append(f"{cluster_id}: No logs found for {pod_name} (current or previous)")

                except Exception as e:
                    log_fetching_details.append(f"Warning: Failed to get logs from {pod_name}: {e}")
                    continue

            self.cloud_provider = provider
            self.log_fetching_details = log_fetching_details
            return pod_analyses if pod_analyses else None

        except Exception as e:
            raise Exception(f"Error analyzing cluster: {str(e)}")

    def _analyze_from_text(self, logs_text: str) -> Optional[RequestAnalysis]:
        """Analyze requests from log text"""
        print("Analyzing requests from provided log text")
        if not logs_text.strip():
            return None
        
        requests = self.parse_requests(logs_text)
        
        if not requests:
            return None
            
        return self.generate_analysis(requests)
    
    def parse_requests(self, logs_text: str) -> List[RequestInfo]:
        """Parse individual requests from log text - only meaningful DB operations"""
        print("Parsing individual requests from log text")
        requests = []
        lines = logs_text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Only process lines that contain meaningful HTTP methods for DB operations
            if not any(method in line for method in ['POST', 'DELETE', 'PATCH', 'PUT']):
                continue
            
            request_info = self.parse_single_request(line)
            if request_info:
                requests.append(request_info)
        
        return requests
    
    def parse_single_request(self, line: str) -> Optional[RequestInfo]:
        """Parse a single request line"""
        try:
            # Check if this is an authorization log (JSON format)
            if '"action":"authorize"' in line:
                return self.parse_auth_request(line)
            
            # Parse istio-proxy access logs
            return self.parse_istio_request(line)
            
        except Exception:
            return None
    
    def parse_auth_request(self, line: str) -> Optional[RequestInfo]:
        """Parse authorization/collection creation logs"""
        try:
            # Extract JSON part
            json_match = re.search(r'\{.*\}', line)
            if not json_match:
                return None
                
            log_data = json.loads(json_match.group())
            
            if log_data.get('action') == 'authorize' and log_data.get('request_action') == 'C':
                # Collection creation
                collection_name = None
                permissions = log_data.get('permissions', [])
                for perm in permissions:
                    resource = perm.get('resource', '')
                    if 'Collection:' in resource:
                        collection_name = re.search(r'Collection:\s*([^]]+)', resource)
                        if collection_name:
                            collection_name = collection_name.group(1).strip()
                            break
                
                return RequestInfo(
                    timestamp=log_data.get('time', ''),
                    method='AUTHORIZE',
                    endpoint='Collection Creation',
                    status_code='200',
                    duration_ms=0,
                    source_ip=log_data.get('source_ip', ''),
                    user_agent='Weaviate Auth',
                    request_id='',
                    collection_name=collection_name,
                    request_type='Collection Creation',
                    details=log_data
                )
        except:
            pass
        
        return None
    
    def parse_istio_request(self, line: str) -> Optional[RequestInfo]:
        """Parse istio-proxy access log format"""
        try:
            # Typical istio format: [timestamp] "METHOD /path HTTP/version" status - details
            timestamp_match = re.search(r'\[([^\]]+)\]', line)
            if not timestamp_match:
                return None
            
            timestamp = timestamp_match.group(1)
            
            # Extract HTTP method and path
            http_match = re.search(r'"([A-Z]+)\s+([^"]+)\s+HTTP/[^"]*"', line)
            if not http_match:
                return None
                
            method = http_match.group(1)
            endpoint = http_match.group(2)
            
            # Extract status code
            status_match = re.search(r'"\s+(\d+)\s+', line)
            status_code = status_match.group(1) if status_match else 'Unknown'
            
            # Extract duration from istio format
            duration_match = re.search(r'"\s+\d+\s+-\s+[^-]+-\s+"[^"]*"\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+"', line)
            if duration_match:
                duration_ms = int(duration_match.group(3))
            else:
                fallback_match = re.search(r'\s+(\d+)\s+(\d+)\s+"([^"]*)"', line)
                duration_ms = int(fallback_match.group(2)) if fallback_match else 0
            
            # Extract source IP
            source_match = re.search(r'"([0-9.,\s]+)"', line)
            source_ip = source_match.group(1).split(',')[0].strip() if source_match else 'Unknown'
            
            # Extract user agent
            ua_match = re.search(r'"[0-9.,\s]+"[^"]*"([^"]+)"', line)
            if not ua_match:
                ua_match = re.search(r'"([^"]*(?:python|grpc|Go-http|curl)[^"]*)"', line)
            user_agent = ua_match.group(1).strip() if ua_match else 'Unknown'
            
            # Extract request ID
            request_id_match = re.search(r'"([a-f0-9-]{36})"', line)
            request_id = request_id_match.group(1) if request_id_match else ''
            
            # Determine request type and extract details
            request_type, collection_name, object_id = self.classify_request(method, endpoint, line)
            
            # Skip non-meaningful requests
            if request_type is None:
                return None
            
            return RequestInfo(
                timestamp=timestamp,
                method=method,
                endpoint=endpoint,
                status_code=status_code,
                duration_ms=duration_ms,
                source_ip=source_ip,
                user_agent=user_agent,
                request_id=request_id,
                collection_name=collection_name,
                object_id=object_id,
                request_type=request_type,
                details={'raw_line': line}
            )
            
        except Exception:
            return None
    
    def classify_request(self, method: str, endpoint: str, full_line: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Classify request type and extract collection/object info - only meaningful DB operations"""
        collection_name = None
        object_id = None
        method_upper = method.upper()

        # Schema Operations - FIXED to properly extract collection name
        if '/v1/schema/' in endpoint and method_upper in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Extract collection name directly from the endpoint path
            schema_match = re.search(r'/v1/schema/([^/?]+)', endpoint)
            if schema_match:
                collection_name = schema_match.group(1)
            
            if method_upper == 'DELETE':
                request_type = 'Schema Delete'
            elif method_upper == 'POST':
                request_type = 'Schema Create'
            elif method_upper == 'PUT':
                request_type = 'Schema Update'
            else:
                request_type = 'Schema Operation'

        # Object Operations
        elif '/v1/objects' in endpoint and method_upper == 'POST':
            if 'consistency_level' in endpoint:
                request_type = 'Single Object Insert'
            else:
                request_type = 'Object Operation'
                
        elif method_upper == 'PATCH' and '/v1/objects' in endpoint:
            request_type = 'Object Update'
            
        elif method_upper == 'DELETE' and '/objects/' in endpoint:
            request_type = 'Object Delete'
            # Extract collection and object ID from path
            delete_match = re.search(r'/indices/([^/]+)/shards/[^/]+/objects/([^/]+)/', endpoint)
            if delete_match:
                collection_name = delete_match.group(1)
                object_id = delete_match.group(2)

        # Batch Operations
        elif '/BatchObjects' in endpoint and method_upper == 'POST':
            request_type = 'Batch Insert'

        elif '/BatchDelete' in endpoint and method_upper == 'POST':
            request_type = 'Batch Delete'

        # Query Operations
        elif '/Search' in endpoint and method_upper == 'POST':
            request_type = 'Search Query'

        elif '/cluster' in endpoint.lower() and method_upper == 'POST':
            request_type = 'Cluster Query'

        else:
            # Skip non-meaningful operations
            return None, None, None

        # Try to extract collection name from various patterns if not already found
        if not collection_name:
            collection_patterns = [
                r'/indices/([^/]+)/',
                r'collection[_\s]*[=:][\s]*["\']?([^"\s,/]+)',
                r'Collection:\s*([^,\]]+)'
            ]
            for pattern in collection_patterns:
                match = re.search(pattern, full_line, re.IGNORECASE)
                if match:
                    collection_name = match.group(1).strip()
                    break

        return request_type, collection_name, object_id
    
    def generate_analysis(self, requests: List[RequestInfo]) -> RequestAnalysis:
        """Generate comprehensive analysis from parsed requests"""
        print("Generating comprehensive analysis from parsed requests")
        if not requests:
            return None
        
        # Basic counts
        total_requests = len(requests)
        request_types = {}
        collections_accessed = {}
        status_codes = {}
        source_ips = {}
        user_agents = {}
        requests_by_type = {}
        requests_by_method = {}  # Added for method filtering
        
        # Performance tracking
        performance_by_type = {}
        
        for request in requests:
            # Count request types
            req_type = request.request_type
            request_types[req_type] = request_types.get(req_type, 0) + 1
            
            # Group requests by type
            if req_type not in requests_by_type:
                requests_by_type[req_type] = []
            requests_by_type[req_type].append(request)
            
            # Group requests by method - ADDED
            method = request.method
            if method not in requests_by_method:
                requests_by_method[method] = []
            requests_by_method[method].append(request)
            
            # Track collections
            if request.collection_name:
                collections_accessed[request.collection_name] = collections_accessed.get(request.collection_name, 0) + 1
            
            # Status codes
            status_codes[request.status_code] = status_codes.get(request.status_code, 0) + 1
            
            # Source IPs
            if request.source_ip != 'Unknown':
                source_ips[request.source_ip] = source_ips.get(request.source_ip, 0) + 1
            
            # User agents
            if request.user_agent != 'Unknown':
                user_agents[request.user_agent] = user_agents.get(request.user_agent, 0) + 1
            
            # Performance tracking
            if req_type not in performance_by_type:
                performance_by_type[req_type] = []
            performance_by_type[req_type].append(request.duration_ms)
        
        # Calculate performance stats
        performance_stats = {}
        for req_type, durations in performance_by_type.items():
            if durations:
                performance_stats[req_type] = {
                    'avg_ms': sum(durations) / len(durations),
                    'min_ms': min(durations),
                    'max_ms': max(durations),
                    'count': len(durations)
                }
        
        # Time range
        timestamps = [r.timestamp for r in requests if r.timestamp]
        time_range = (min(timestamps), max(timestamps)) if timestamps else ('Unknown', 'Unknown')
        
        # Generate summary
        summary = self._generate_summary(request_types, collections_accessed, status_codes, performance_stats, time_range)
        
        return RequestAnalysis(
            total_requests=total_requests,
            request_types=request_types,
            collections_accessed=collections_accessed,
            status_codes=status_codes,
            source_ips=source_ips,
            user_agents=user_agents,
            time_range=time_range,
            requests_by_type=requests_by_type,
            requests_by_method=requests_by_method,  # Added
            performance_stats=performance_stats,
            summary=summary
        )
    
    def _generate_summary(self, request_types: Dict[str, int], collections: Dict[str, int], 
                         status_codes: Dict[str, int], performance: Dict[str, Dict], 
                         time_range: Tuple[str, str]) -> str:
        """Generate text summary of the analysis"""
        summary_parts = []
        
        # Request overview
        total = sum(request_types.values())
        summary_parts.append(f"📊 REQUESTS SUMMARY ({total} total requests)")
        summary_parts.append(f"⏰ Time Range: {time_range[0]} → {time_range[1]}")
        summary_parts.append("")
        
        # Top request types
        sorted_types = sorted(request_types.items(), key=lambda x: x[1], reverse=True)
        summary_parts.append("🔥 TOP REQUEST TYPES:")
        for req_type, count in sorted_types[:5]:
            percentage = (count / total) * 100
            summary_parts.append(f"   • {req_type}: {count} ({percentage:.1f}%)")
        summary_parts.append("")
        
        # Collections accessed
        if collections:
            summary_parts.append("📦 COLLECTIONS ACCESSED:")
            sorted_collections = sorted(collections.items(), key=lambda x: x[1], reverse=True)
            for collection, count in sorted_collections[:5]:
                summary_parts.append(f"   • {collection}: {count} requests")
            summary_parts.append("")
        
        # Status codes
        summary_parts.append("📡 STATUS CODES:")
        sorted_status = sorted(status_codes.items(), key=lambda x: x[1], reverse=True)
        for status, count in sorted_status:
            emoji = "✅" if status.startswith('2') else "⚠️" if status.startswith('4') else "❌"
            percentage = (count / total) * 100
            summary_parts.append(f"   {emoji} {status}: {count} ({percentage:.1f}%)")
        summary_parts.append("")
        
        # Performance insights
        if performance:
            summary_parts.append("⚡ PERFORMANCE INSIGHTS:")
            slowest_ops = sorted(performance.items(), key=lambda x: x[1]['avg_ms'], reverse=True)
            for op_type, stats in slowest_ops[:3]:
                summary_parts.append(f"   • {op_type}: avg {stats['avg_ms']:.0f}ms (max: {stats['max_ms']}ms)")
        
        return "\n".join(summary_parts)
    
    def create_requests_dataframe(self, requests: List[RequestInfo]) -> pd.DataFrame:
        """Create DataFrame for displaying requests"""
        data = []
        
        for request in requests:
            # Format timestamp for display
            time_display = request.timestamp
            if 'T' in time_display:
                time_display = time_display.split('T')[1][:8]  # Show just time part
            
            # Format duration with minutes if over 1000ms
            duration_display = self._format_duration(request.duration_ms)
            
            data.append({
                'Time': time_display,
                'Method': request.method,
                'Endpoint': request.endpoint,
                'Status': request.status_code,
                'Duration': duration_display,
                'Collection': request.collection_name or '-',
                'Object ID': request.object_id or '-',
                'Source IP': request.source_ip,
                'Request Type': request.request_type
            })
        
        return pd.DataFrame(data)
    
    def _format_duration(self, duration_ms: int) -> str:
        """Format duration with minutes if over 1000ms"""
        if duration_ms >= 1000:
            minutes = duration_ms / 60000
            if minutes >= 1:
                return f"{minutes:.1f}min"
            else:
                seconds = duration_ms / 1000
                return f"{seconds:.1f}s"
        else:
            return f"{duration_ms}ms"
    
    def create_summary_dataframe(self, analysis: RequestAnalysis) -> pd.DataFrame:
        """Create summary DataFrame"""
        data = []
        
        # Request types summary
        for req_type, count in sorted(analysis.request_types.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / analysis.total_requests) * 100
            avg_duration = 0
            if req_type in analysis.performance_stats:
                avg_duration = analysis.performance_stats[req_type]['avg_ms']
            
            data.append({
                'Request Type': req_type,
                'Count': count,
                'Percentage': f"{percentage:.1f}%",
                'Avg Duration': self._format_duration(avg_duration) if avg_duration > 0 else "-"
            })
        
        return pd.DataFrame(data)
