
from typing import Dict, List, Optional, Any
from extractors.panic_log_extractor import PanicLogExtractor
import re
import json
from dataclasses import dataclass

class LogPanicDetector:
    """Detects panic traces within analyzed logs"""
    def __init__(self):
        self.log_extractor = PanicLogExtractor()

    def detect_panics_in_pod_analysis(self, pod_analysis: Dict) -> List[str]:
        """Extract panic traces from pod analysis results"""
        print("Detecting panics in pod analysis")
        all_raw_logs = []
        for level_summaries in pod_analysis['summaries'].values():
            for summary in level_summaries:
                if summary.sample_raw:
                    all_raw_logs.append(summary.sample_raw)
        combined_logs = '\n'.join(all_raw_logs)
        panics = self.log_extractor.parse_panic_sections(combined_logs)
        return panics

class PanicAnalyzer:
    """Analyzes panic information"""

    def analyze(self, panic_info, code_context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform simple analysis of a panic"""
        print("Analyzing panic...")
        analysis = {
            'panic_info': panic_info,
            'code_context': code_context,
            'summary': self.create_summary(panic_info),
            'locations_to_check': self.get_locations_to_check(panic_info)
        }
        return analysis

    def create_summary(self, panic_info) -> str:
        """Create a summary of what happened"""
        print("Creating panic summary...")
        summary = f"**Type:** {panic_info.panic_type}\n"
        summary += f"**Error:** {panic_info.error_message}\n"
        summary += f"**Location:** {panic_info.function_name} at line {panic_info.line_number}\n"
        summary += f"**File:** {panic_info.file_path.split('/')[-1]}"
        return summary

    def get_locations_to_check(self, panic_info) -> list:
        """Get stack trace locations in ORDER as they appear"""
        print("Extracting locations to check from panic info...")
        locations = []
        seen_files = set()
        for line in panic_info.stack_trace:
            if '.go:' in line and 'runtime' not in line:
                match = re.search(r'([^\s]+\.go):\d+', line)
                if match:
                    file_name = match.group(1).split('/')[-1]
                    if file_name not in seen_files:
                        locations.append(line.strip())
                        seen_files.add(file_name)
        return locations

@dataclass
class PanicInfo:
    """Contains parsed panic information"""
    error_message: str
    panic_type: str
    panic_detail: str
    file_path: str
    line_number: int
    function_name: str
    stack_trace: List[str]
    raw_panic: str
    pod_name: Optional[str] = None
    severity: Optional[str] = None
    weaviate_version: Optional[str] = None
    build_info: Optional[Dict[str, str]] = None

    @property
    def github_url(self) -> str:
        """Generate GitHub URL for this location"""
        print("Generating GitHub URL for panic location...")
        if self.file_path.startswith("/go/src/github.com/weaviate/weaviate/"):
            relative_path = self.file_path.replace("/go/src/github.com/weaviate/weaviate/", "")
        else:
            parts = self.file_path.split("weaviate/weaviate/")
            relative_path = parts[-1] if len(parts) > 1 else self.file_path
        
        return f"https://github.com/weaviate/weaviate/blob/main/{relative_path}#L{self.line_number}"


class PanicParser:
    """Parses Go panic stack traces"""
    
    def parse_panic(self, panic_text: str, pod_name: Optional[str] = None) -> Optional[PanicInfo]:
        """Parse a panic stack trace into structured information"""
        print("Parsing panic stack trace...")
        try:
            error_message = self.extract_error_message(panic_text)
            panic_type, panic_detail = self.determine_panic_type(error_message)
            severity = self.determine_severity(panic_text, error_message)
            stack_trace = self.extract_stack_trace(panic_text)
            location = self.extract_location(panic_text, stack_trace)
            build_info = self.extract_build_info(panic_text)
            
            if not location:
                return None
            
            return PanicInfo(
                error_message=error_message,
                panic_type=panic_type,
                panic_detail=panic_detail,
                severity=severity,
                file_path=location['file_path'],
                line_number=location['line_number'],
                function_name=location['function_name'],
                stack_trace=stack_trace,
                raw_panic=panic_text,
                pod_name=pod_name,
                weaviate_version=build_info.get('build_wv_version') if build_info else None,
                build_info=build_info
            )
        except Exception:
            return None
    
    def determine_severity(self, panic_text: str, error_message: str) -> str:
        """Determine panic severity based on content"""
        print("Determining panic severity...")
        text_lower = panic_text.lower()
        error_lower = error_message.lower()
        
        # Check for recovery status
        if 'recovered from panic' in text_lower:
            return "\u26a0\ufe0f WARNING (Recovered)"
        elif 'panic recovered' in text_lower:
            return "\u26a0\ufe0f WARNING (Auto-recovered)"
        
        # Check for critical patterns
        if any(word in error_lower for word in ['corruption', 'fatal', 'critical', 'data loss']):
            return "\ud83d\udd34 CRITICAL"
        elif any(word in error_lower for word in ['shard', 'replication', 'cluster', 'database']):
            return "\ud83d\udd34 HIGH"
        elif any(word in error_lower for word in ['nil pointer', 'index out of range', 'runtime error']):
            return "\ud83d\udfe1 MEDIUM"
        
        # Active panic vs recovered
        if 'goroutine' in text_lower and 'running' in text_lower:
            return "\ud83d\udd34 ACTIVE PANIC"
        
        return "\ud83d\udfe1 MEDIUM"
    
    def extract_build_info(self, panic_text: str) -> Dict[str, str]:
        """
        Extract Weaviate build information from panic text if present.
        """
        print("Extracting Weaviate build information...")
        build_info = {}
        lines = panic_text.split('\n')
        
        for line in lines:
            if '"build_' in line and '{' in line:
                try:
                    json_str = line[line.find('{'):]
                    data = json.loads(json_str)
                    for key, value in data.items():
                        if key.startswith('build_'):
                            build_info[key] = value
                except:
                    pass
        
        return build_info
    
    def extract_error_message(self, panic_text: str) -> str:
        """Extract the main error message from panic text"""
        print("Extracting error message from panic text...")
        lines = panic_text.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            if ('"panic":' in line_lower or '"error":' in line_lower or '"msg":' in line_lower) and '{' in line:
                try:
                    json_str = line[line.find('{'):]
                    data = json.loads(json_str)
                    
                    if 'panic' in data:
                        return data['panic']
                    if 'error' in data:
                        return data['error']
                    if 'msg' in data:
                        msg_lower = data['msg'].lower()
                        if 'recovered from panic' in msg_lower and 'panic:' in msg_lower:
                            return data['msg'].split('panic:')[1].strip()
                        return data['msg']
                except:
                    pass
            
            if 'panic:' in line_lower:
                match = re.search(r'panic:\s*(.*)', line, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
            
            if 'recovered from panic:' in line_lower:
                return line.split('recovered from panic:')[1].strip()
            
            if 'runtime error:' in line_lower:
                return line.strip()
        
        for line in lines:
            if line.strip() and not line.strip().startswith('{'):
                return line.strip()
        
        return "Unknown panic"
    
    def determine_panic_type(self, error_message: str) -> tuple[str, str]:
        """Return (type, detail) for the panic, minimal and clear."""
        print("Determining panic type and detail...")
        error_lower = error_message.lower()
        if 'runtime error:' in error_lower:
            type_ = 'runtime error'
            detail = error_message.split('runtime error:')[1].strip() if 'runtime error:' in error_message else error_message
            detail = ' '.join(detail.split()[:5])
            return type_, detail
        if 'panic:' in error_lower:
            type_ = 'panic'
            detail = error_message.split('panic:')[1].strip() if 'panic:' in error_message else error_message
            detail = ' '.join(detail.split()[:5])
            return type_, detail
        if ':' in error_message:
            type_, detail = error_message.split(':', 1)
            return type_.strip(), ' '.join(detail.strip().split()[:5])
        return error_message.strip(), ''
    
    def extract_stack_trace(self, panic_text: str) -> List[str]:
        """Extract the stack trace lines"""
        print("Extracting stack trace from panic text...")
        lines = panic_text.split('\n')
        stack_lines = []
        
        in_stack = False
        for line in lines:
            if 'goroutine' in line.lower() and '[running]' in line.lower():
                in_stack = True
            
            if in_stack and line.strip():
                if any(marker in line.lower() for marker in ['panic recovered', 'created by']):
                    break
                stack_lines.append(line)
        
        return stack_lines
    
    def extract_location(self, panic_text: str, stack_trace: List[str]) -> Optional[Dict[str, Any]]:
        """Extract the location where panic occurred"""
        print("Extracting location of panic...")
        file_pattern = r'([^\s]+\.go):(\d+)'
        
        for line in stack_trace[:10]:
            match = re.search(file_pattern, line)
            if match:
                file_path = match.group(1)
                line_number = int(match.group(2))
                
                if 'runtime/' in file_path or 'panic.go' in file_path:
                    continue
                
                function_name = "unknown"
                lines = panic_text.split('\n')
                for i, l in enumerate(lines):
                    if file_path in l and f":{line_number}" in l and i > 0:
                        func_line = lines[i-1].strip()
                        func_line = re.sub(r'\(.*\)$', '', func_line)
                        parts = func_line.split('.')
                        if len(parts) > 1:
                            function_name = parts[-1].strip()
                        break
                
                return {
                    'file_path': file_path,
                    'line_number': line_number,
                    'function_name': function_name
                }
        
        return None
    
    def deduplicate_panics(self, panics: List[PanicInfo]) -> List[tuple]:
        """Deduplicate panics and count occurrences"""
        print("Deduplicating panics...")
        unique_panics = {}
        
        for panic in panics:
            key = (panic.file_path, panic.line_number, panic.error_message[:50])
            
            if key not in unique_panics:
                unique_panics[key] = {'panic': panic, 'count': 0}
            unique_panics[key]['count'] += 1
        
        result = [(v['panic'], v['count']) for v in unique_panics.values()]
        result.sort(key=lambda x: x[1], reverse=True)
        
        return result
