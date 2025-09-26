import subprocess
import re
from typing import List, Dict


class PanicLogExtractor:
    """Handles extraction of logs from Weaviate clusters"""

    def auto_detect_pod_names(self, cluster_id: str) -> List[str]:
        """Auto-detect available Weaviate pods in the current context. E.g. pod/weaviate-0 -> weaviate-0"""
        print(f"Auto-detecting pods in cluster: {cluster_id}")
        try:
            # First establish kube context
            setup_cmd = ["wcs", "cluster", cluster_id, "--kube"]
            setup_result = subprocess.run(setup_cmd, capture_output=True, text=True)
            if setup_result.returncode != 0:
                raise Exception(f"Failed to connect to cluster: {setup_result.stderr}")

            # Then get pods (namespace set by wcs cluster command)
            cmd = ["kubectl", "get", "pods", "-l", "app=weaviate", "-o", "name"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                pod_names = []
                for line in result.stdout.strip().split('\n'):
                    if line and line.startswith('pod/'):
                        pod_names.append(line[4:])  # Remove 'pod/' prefix
                return pod_names
            elif result.returncode != 0:
                raise Exception(f"Failed to get pods: {result.stderr}")
            
        except Exception as e:
            raise Exception(str(e))
            
        return []

    def extract_panics_from_cluster(self, cluster_id: str, pod_name: str = None, days: int = 1,
                                  include_current: bool = True, include_previous: bool = True) -> Dict[str, List[str]]:
        """Extract logs from a Weaviate cluster with options for pod and log type selection"""
        print(f"Extracting panic logs from cluster: {cluster_id}, pod: {pod_name}, days: {days}, current: {include_current}, previous: {include_previous}")
        try:
            # Establish kube context
            cmd = ["wcs", "cluster", cluster_id, "--kube"]
            setup_result = subprocess.run(cmd, capture_output=True, text=True)
            if setup_result.returncode != 0:
                raise Exception(f"Failed to connect to cluster: {setup_result.stderr}")

            # Get pod names
            cmd = ["kubectl", "get", "pods", "-l", "app=weaviate", "-o", "name"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Failed to get pods: {result.stderr}")

            pods = [name[4:] for name in result.stdout.strip().split('\n') if name.startswith('pod/')]
            if pod_name:
                pods = [pod_name] if pod_name in pods else []
            
            if not pods:
                return {}

            # Extract panics from each pod
            all_panics = {}
            for pod in pods:
                pod_panics = []
                
                # Convert days to hours for --since parameter
                since_hours = days * 24

                if include_current:
                    # Current logs with hours parameter
                    cmd = ["kubectl", "logs", pod, "--since", f"{since_hours}h"]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        panics = self.parse_panic_sections(result.stdout)
                        pod_panics.extend(panics)

                if include_previous:
                    # Previous logs with hours parameter
                    cmd = ["kubectl", "logs", pod, "--previous", "--since", f"{since_hours}h"]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        panics = self.parse_panic_sections(result.stdout)
                        if panics:
                            pod_panics.extend(panics)
                
                if pod_panics:
                    all_panics[pod] = pod_panics

            return all_panics

        except Exception as e:
            raise Exception(f"Failed to extract logs: {str(e)}")

    def extract_from_text(self, panic_text: str) -> List[str]:
        """Extract panics from manually pasted text"""
        print("Extracting panics from provided text")
        # A more reliable check for Go panics
        if 'goroutine' in panic_text and ('[running]' in panic_text or 'created by' in panic_text):
            return self.parse_panic_sections(panic_text)
        elif 'panic:' in panic_text.lower():
             return self.parse_panic_sections(panic_text)
        return []

    def parse_panic_sections(self, logs: str) -> List[str]:
        """Parse log output by grouping lines into entries first, then checking for panic signatures."""
        print("Parsing panic sections")
        panics = []
        current_entry_lines = []
        lines = logs.split('\n')

        for line in lines:
            if not line.strip():
                continue

            # If the line looks like a new entry, process the previous one
            if self.is_new_log_entry(line) and current_entry_lines:
                full_entry = '\n'.join(current_entry_lines)
                # Check for panic signatures in the complete entry
                if 'goroutine' in full_entry and '[running]' in full_entry:
                    panics.append(full_entry)
                
                # Start a new entry
                current_entry_lines = [line]
            else:
                # Continue building the current entry
                current_entry_lines.append(line)

        # Process the very last entry in the log file
        if current_entry_lines:
            full_entry = '\n'.join(current_entry_lines)
            if 'goroutine' in full_entry and '[running]' in full_entry:
                panics.append(full_entry)

        return panics


    def is_new_log_entry(self, line: str) -> bool:
        """Check if a line is the start of a new log entry"""
        patterns = [
            r'^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}', # e.g., 2025-09-05 14:17:41.880
            r'^\d{4}[-/]\d{2}[-/]\d{2}',
            r'^\[\w+\]',
            r'^time=',
            r'^level=',
            r'^\{"time":',
        ]
        return any(re.match(pattern, line) for pattern in patterns)
