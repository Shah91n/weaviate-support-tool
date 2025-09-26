import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict


@dataclass
class LogEntry:
    """Contains parsed log entry information"""
    level: str
    message: str
    timestamp: str
    pod_name: Optional[str] = None
    weaviate_version: Optional[str] = None
    raw_log: str = ""
    metadata: Optional[Dict[str, Any]] = None
    log_type: Optional[str] = None

    @property
    def message_key(self) -> str:
        """Generate key for deduplication based on message content"""
        # Clean the message for deduplication
        clean_msg = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'TIMESTAMP', self.message)
        clean_msg = re.sub(r'\b\d+\b', 'NUMBER', clean_msg)
        clean_msg = re.sub(r'[a-f0-9\-]{36}', 'UUID', clean_msg)
        return clean_msg.strip()


@dataclass
class CollectionClassTenantEntry:
    """Entry for collection/class/tenant log analysis"""
    entity_type: str  # "collection", "class", "tenant"
    entity_name: str
    log_entries: List[LogEntry]
    first_timestamp: str
    latest_timestamp: str
    log_levels: List[str]
    sample_messages: List[str]

    @property
    def count(self) -> int:
        return len(self.log_entries)


@dataclass
class LogSummary:
    """Summary of deduplicated logs"""
    message: str
    level: str
    count: int
    first_timestamp: str
    latest_timestamp: str
    pod_names: List[str]
    sample_raw: str = ""
    metadata_keys: Dict[str, Any] = None
    log_type: Optional[str] = None

    def __post_init__(self):
        if self.metadata_keys is None:
            self.metadata_keys = {}


class LogAnalyzer:
    """Analyzes Weaviate logs with smart deduplication and categorization"""

    def __init__(self):
        self.logs_by_pod: Dict[str, List[LogEntry]] = defaultdict(list)
        self.pod_metadata: Dict[str, Dict[str, Any]] = defaultdict(dict)

    def analyze_logs(self, raw_logs: str, pod_name: Optional[str] = None, log_type: Optional[str] = None) -> Dict[str, Any]:
        """Main entry point for log analysis"""
        print("Starting log analysis...")
        # Parse raw logs into structured entries
        log_entries = self.parse_logs(raw_logs, pod_name, log_type=log_type)
        
        # Organize by pod
        for entry in log_entries:
            pod = entry.pod_name or pod_name or "unknown"
            self.logs_by_pod[pod].append(entry)
            
            # Extract metadata
            if entry.weaviate_version:
                self.pod_metadata[pod]['weaviate_version'] = entry.weaviate_version

        # Generate analysis
        return self.generate_analysis()

    def parse_logs(self, raw_logs: str, default_pod: Optional[str] = None, log_type: Optional[str] = None) -> List[LogEntry]:
        """Parse raw log text into structured LogEntry objects"""
        print("Parsing logs...")
        entries = []
        lines = raw_logs.strip().split('\n')

        for line in lines:
            if not line.strip():
                continue

            entry = self.parse_single_log_line(line, default_pod, log_type=log_type)
            if entry:
                entries.append(entry)

        return entries

    def parse_single_log_line(self, line: str, default_pod: Optional[str] = None, log_type: Optional[str] = None) -> Optional[LogEntry]:
        """Parse a single log line"""
        try:
            # Try JSON parsing first
            if line.strip().startswith('{'):
                return self.parse_json_log(line, default_pod, log_type=log_type)
            
            # Try structured text parsing
            return self.parse_text_log(line, default_pod, log_type=log_type)
            
        except Exception:
            # Fallback for unparseable lines
            return LogEntry(
                level="info",
                message=line.strip(),
                timestamp=datetime.now().isoformat(),
                pod_name=default_pod,
                raw_log=line,
                log_type=log_type
            )

    def parse_json_log(self, line: str, default_pod: Optional[str] = None, log_type: Optional[str] = None) -> Optional[LogEntry]:
        """Parse JSON formatted log line"""
        print("Parsing JSON line:", line)
        try:
            # Handle lines that might have prefix before JSON
            json_start = line.find('{')
            if json_start == -1:
                return None
                
            json_str = line[json_start:]
            data = json.loads(json_str)

            # Extract standard fields
            level = data.get('level', 'info').lower()
            message = data.get('msg', data.get('message', ''))
            
            # Check for error field and append to message
            error_field = data.get('error', '')
            if error_field and error_field not in message:
                message = f"{message} | Error: {error_field}" if message else f"Error: {error_field}"
            
            timestamp = data.get('time', data.get('timestamp', ''))
            
            # Extract metadata (all fields except standard ones)
            weaviate_version = None
            metadata = {}
            
            for key, value in data.items():
                if key.startswith('build_') and 'version' in key:
                    weaviate_version = str(value)
                elif key not in ['level', 'msg', 'message', 'time', 'timestamp', 'error']:
                    metadata[key] = value

            # Try to extract pod name from message or metadata
            pod_name = default_pod
            if not pod_name:
                pod_name = self.extract_pod_name(message, metadata)

            return LogEntry(
                level=level,
                message=message,
                timestamp=timestamp,
                pod_name=pod_name,
                weaviate_version=weaviate_version,
                metadata=metadata,
                raw_log=line,
                log_type=log_type
            )

        except json.JSONDecodeError:
            return None

    def parse_text_log(self, line: str, default_pod: Optional[str] = None, log_type: Optional[str] = None) -> Optional[LogEntry]:
        """Parse non-JSON log lines"""
        print("Parsing text line:", line)
        # Common patterns for text logs
        patterns = [
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[Z\d\.\+\-:]*)\s+(INFO|WARN|ERROR|DEBUG)\s+(.+)',
            r'\[(\w+)\]\s+(.+)',
            r'(\w+):\s+(.+)',
        ]

        for pattern in patterns:
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                if len(match.groups()) == 3:  # timestamp, level, message
                    timestamp, level, message = match.groups()
                elif len(match.groups()) == 2:  # level, message
                    level, message = match.groups()
                    timestamp = datetime.now().isoformat()
                else:
                    continue

                return LogEntry(
                    level=level.lower(),
                    message=message.strip(),
                    timestamp=timestamp,
                    pod_name=default_pod,
                    raw_log=line,
                    log_type=log_type
                )

        # Fallback
        return LogEntry(
            level="info",
            message=line.strip(),
            timestamp=datetime.now().isoformat(),
            pod_name=default_pod,
            raw_log=line,
            log_type=log_type
        )

    def extract_pod_name(self, message: str, metadata: Dict[str, Any]) -> Optional[str]:
        """Extract pod name from message or metadata"""
        print("Extracting pod name from message and metadata...")
        # Check metadata first
        for key, value in metadata.items():
            if 'pod' in key.lower() and isinstance(value, str):
                return value

        # Check message for pod patterns
        pod_patterns = [
            r'weaviate-(\d+)',
            r'pod[:\s]+([^\s,]+)',
            r'node[:\s]+([^\s,]+)',
        ]

        for pattern in pod_patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return f"weaviate-{match.group(1)}" if match.group(1).isdigit() else match.group(1)

        return None

    def generate_analysis(self) -> Dict[str, Any]:
        """Generate comprehensive analysis of all logs"""
        print("Generating log analysis report...")
        analysis = {
            'total_pods': len(self.logs_by_pod),
            'pod_summaries': {},
            'global_stats': self.calculate_global_stats(),
            'collections_classes_tenants': self.analyze_collections_classes_tenants()
        }

        for pod_name, logs in self.logs_by_pod.items():
            analysis['pod_summaries'][pod_name] = self.analyze_pod_logs(pod_name, logs)

        return analysis

    def analyze_pod_logs(self, pod_name: str, logs: List[LogEntry]) -> Dict[str, Any]:
        """Analyze logs for a specific pod"""
        print("Analyzing logs for pod:", pod_name)
        # Categorize by level
        by_level = defaultdict(list)
        for log in logs:
            by_level[log.level].append(log)

        # Deduplicate and summarize
        summaries = {
            'info': self.deduplicate_logs(by_level['info']),
            'warning': self.deduplicate_logs(by_level.get('warn', []) + by_level.get('warning', [])),
            'error': self.deduplicate_logs(by_level['error'])
        }

        # Extract metadata
        metadata = self.pod_metadata.get(pod_name, {})
        if not metadata.get('weaviate_version'):
            # Try to find version in logs
            for log in logs:
                if log.weaviate_version:
                    metadata['weaviate_version'] = log.weaviate_version
                    break

        return {
            'pod_name': pod_name,
            'metadata': metadata,
            'total_logs': len(logs),
            'counts': {level: len(logs) for level, logs in by_level.items()},
            'summaries': summaries,
            'time_range': self.get_time_range(logs)
        }

    def deduplicate_logs(self, logs: List[LogEntry]) -> List[LogSummary]:
        """Smart deduplication of log entries"""
        print("Deduplicating logs...")
        if not logs:
            return []

        # Group by message content
        groups = defaultdict(list)
        for log in logs:
            groups[log.message_key].append(log)

        summaries = []
        for message_key, group_logs in groups.items():
            if not group_logs:
                continue

            # Sort by timestamp
            group_logs.sort(key=lambda x: x.timestamp)
            
            # Create summary
            first_log = group_logs[0]
            latest_log = group_logs[-1]
            
            pod_names = list(set(log.pod_name for log in group_logs if log.pod_name))
            
            # Collect all metadata keys from the group
            all_metadata = {}
            for log in group_logs:
                if log.metadata:
                    for key, value in log.metadata.items():
                        if key not in all_metadata:
                            all_metadata[key] = value
            
            summary = LogSummary(
                message=first_log.message,
                level=first_log.level,
                count=len(group_logs),
                first_timestamp=first_log.timestamp,
                latest_timestamp=latest_log.timestamp,
                pod_names=pod_names,
                sample_raw=latest_log.raw_log,
                metadata_keys=all_metadata,
                log_type=first_log.log_type
            )
            summaries.append(summary)

        # Sort by priority: errors first (by latest time), then by count
        summaries.sort(key=lambda x: (
            x.level != 'error',  # errors first
            -x.count,  # then by count (descending)
            x.latest_timestamp  # then by latest time
        ))

        return summaries

    def get_time_range(self, logs: List[LogEntry]) -> Dict[str, str]:
        """Get time range for logs"""
        print("Calculating time range for logs...")
        if not logs:
            return {}

        timestamps = [log.timestamp for log in logs if log.timestamp]
        if not timestamps:
            return {}

        return {
            'start': min(timestamps),
            'end': max(timestamps)
        }

    def calculate_global_stats(self) -> Dict[str, Any]:
        """Calculate global statistics across all pods"""
        print("Calculating global statistics...")
        total_logs = sum(len(logs) for logs in self.logs_by_pod.values())
        
        level_counts = defaultdict(int)
        for logs in self.logs_by_pod.values():
            for log in logs:
                level_counts[log.level] += 1

        return {
            'total_logs': total_logs,
            'level_distribution': dict(level_counts),
            'active_pods': list(self.logs_by_pod.keys())
        }

    def analyze_collections_classes_tenants(self) -> Dict[str, List[CollectionClassTenantEntry]]:
        """Analyze all logs that mention collections, classes, or tenants"""
        print("Analyzing collections, classes, and tenants...")
        collections = defaultdict(list)
        classes = defaultdict(list)
        tenants = defaultdict(list)
        
        # Patterns to match collection/class/tenant mentions
        collection_patterns = [
            r'"collection":\s*"([^"]+)"',
            r'"className":\s*"([^"]+)"',
            r'collection\s*=\s*"([^"]+)"',
            r'collection:\s*([^\s,}]+)',
            r'Collection\s*:\s*([^\s,}]+)',
            r'collection\s+([A-Za-z][A-Za-z0-9_]*)',
        ]
        
        class_patterns = [
            r'"class":\s*"([^"]+)"',
            r'"className":\s*"([^"]+)"',
            r'class\s*=\s*"([^"]+)"',
            r'class:\s*([^\s,}]+)',
            r'Class\s*:\s*([^\s,}]+)',
            r'class\s+([A-Za-z][A-Za-z0-9_]*)',
        ]
        
        tenant_patterns = [
            r'"tenant":\s*"([^"]+)"',
            r'"tenantId":\s*"([^"]+)"',
            r'"tenant_id":\s*"([^"]+)"',
            r'tenant\s*=\s*"([^"]+)"',
            r'tenant:\s*([^\s,}]+)',
            r'Tenant\s*:\s*([^\s,}]+)',
            r'tenant\s+([a-f0-9\-]{36})',
        ]
        
        # Process all logs from all pods
        for pod_name, logs in self.logs_by_pod.items():
            for log in logs:
                # Check log message and metadata for mentions
                search_text = log.message
                if log.raw_log:
                    search_text += " " + log.raw_log
                if log.metadata:
                    search_text += " " + str(log.metadata)
                
                # Search for collections
                for pattern in collection_patterns:
                    matches = re.finditer(pattern, search_text, re.IGNORECASE)
                    for match in matches:
                        collection_name = match.group(1).strip()
                        if collection_name and len(collection_name) > 1:
                            collections[collection_name].append(log)
                
                def clean_entity_name(name):
                    """Clean entity names by removing quotes, brackets, etc."""
                    if not name:
                        return None
                    # Remove quotes, brackets, and other special characters
                    clean = re.sub(r'[\"\'\[\]\\]+', '', name.strip())
                    # Remove any remaining whitespace
                    clean = clean.strip()
                    return clean if clean and clean != '*' else None

                # Check for collections
                for pattern in collection_patterns:
                    matches = re.finditer(pattern, search_text, re.IGNORECASE)
                    for match in matches:
                        collection_name = clean_entity_name(match.group(1))
                        if collection_name and len(collection_name) > 1:
                            collections[collection_name].append(log)
                
                # Search for classes
                for pattern in class_patterns:
                    matches = re.finditer(pattern, search_text, re.IGNORECASE)
                    for match in matches:
                        class_name = clean_entity_name(match.group(1))
                        if class_name and len(class_name) > 1 and class_name not in ['doc', 'log', 'msg']:
                            classes[class_name].append(log)
                
                # Search for tenants
                for pattern in tenant_patterns:
                    matches = re.finditer(pattern, search_text, re.IGNORECASE)
                    for match in matches:
                        tenant_id = clean_entity_name(match.group(1))
                        if tenant_id and len(tenant_id) > 3:
                            tenants[tenant_id].append(log)
        
        # Convert to CollectionClassTenantEntry objects
        def create_entries(data_dict: Dict[str, List[LogEntry]], entity_type: str) -> List[CollectionClassTenantEntry]:
            print(f"Creating entries for {entity_type}s...")
            entries = []
            for name, logs in data_dict.items():
                if logs:  # Only include if we have logs
                    # Remove duplicates while preserving order
                    unique_logs = []
                    seen = set()
                    for log in logs:
                        log_key = (log.timestamp, log.message)
                        if log_key not in seen:
                            seen.add(log_key)
                            unique_logs.append(log)
                    
                    if unique_logs:  # Only create entry if we have unique logs
                        timestamps = [log.timestamp for log in unique_logs]
                        levels = [log.level for log in unique_logs]
                        messages = [log.message[:200] + "..." if len(log.message) > 200 else log.message 
                                  for log in unique_logs[:3]]
                        
                        entry = CollectionClassTenantEntry(
                            entity_type=entity_type,
                            entity_name=name,
                            log_entries=unique_logs,
                            first_timestamp=min(timestamps),
                            latest_timestamp=max(timestamps),
                            log_levels=levels,
                            sample_messages=messages
                        )
                        entries.append(entry)
            
            # Sort by count (descending)
            return sorted(entries, key=lambda x: x.count, reverse=True)
        
        return {
            'collections': create_entries(collections, 'collection'),
            'classes': create_entries(classes, 'class'),
            'tenants': create_entries(tenants, 'tenant')
        }
