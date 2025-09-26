import subprocess
import re
from typing import List, Dict
from collections import defaultdict

class LogExtractor():
    """Log extractor for log analysis"""

    def extract_logs_by_pod_id(self, pod_id: str) -> Dict[str, str]:
        """Extract logs from specific pod ID (e.g., weaviate-0, weaviate-1)"""
        print(f"Extracting logs from pod ID: {pod_id}")
        try:
            # Handle both full pod names and just numbers
            if pod_id.isdigit():
                pod_name = f"weaviate-{pod_id}"
            else:
                pod_name = pod_id

            # Get logs from the pod
            cmd = ["kubectl", "logs", pod_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return {pod_name: result.stdout}
            else:
                return {}
            
        except Exception as e:
            raise Exception(f"Failed to extract logs from pod {pod_id}: {str(e)}")

    def extract_logs_from_multiple_pods(self, pod_ids: List[str]) -> Dict[str, str]:
        """Extract logs from multiple pods"""
        print(f"Extracting logs from pods: {', '.join(pod_ids)}")
        all_logs = {}
        
        for pod_id in pod_ids:
            try:
                pod_logs = self.extract_logs_by_pod_id(pod_id)
                all_logs.update(pod_logs)
            except Exception as e:
                # Continue with other pods even if one fails
                print(f"Warning: Failed to get logs from {pod_id}: {e}")
                continue
                
        return all_logs

    def extract_logs_from_cluster_analysis(self, cluster_id: str, days: int = None, pod_name: str = None, previous: bool = False) -> Dict[str, str]:
        """Extract logs from all or specific Weaviate pods in a cluster for analysis. If pod_name is given, only that pod is fetched. If previous=True, uses --previous flag."""
        print(f"Extracting logs from cluster: {cluster_id}, pod: {pod_name}, days: {days}, previous: {previous}")
        try:
            # Establish kube context
            cmd = ["wcs", "cluster", cluster_id, "--kube"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            # Get pod names
            cmd = [
                "kubectl", "get", "pods",
                "-l", "app=weaviate",
                "-n", cluster_id,
                "-o", "jsonpath={.items[*].metadata.name}"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                raise Exception("Failed to get pod list")
            pods = result.stdout.strip().split()
            if not pods:
                return {}

            # If pod_name specified, filter pods
            if pod_name:
                pods = [pod_name] if pod_name in pods else []
            # Calculate hours for since parameter (applies to both current and previous logs)
            since_hours = days * 24 if days else None

            # Extract logs from each pod
            all_logs = {}
            for pod in pods:
                try:
                    cmd = ["kubectl", "logs", pod, "-n", cluster_id]
                    if since_hours:
                        cmd.extend([f"--since={since_hours}h"])
                    if previous:
                        cmd.append("--previous")  # Only previous logs if flag is set
                    # This means: previous=True gets previous logs, previous=False gets current logs, both respect --since
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    if result.returncode == 0 and result.stdout.strip():
                        all_logs[pod] = result.stdout
                except Exception as e:
                    print(f"Warning: Failed to get logs from pod {pod}: {e}")
                    continue
            return all_logs
        except Exception as e:
            raise Exception(f"Failed to extract cluster logs: {str(e)}")

    def extract_from_text_analysis(self, log_text: str) -> Dict[str, str]:
        """Extract logs from manual text input for analysis"""
        print("Extracting logs from provided text input (Manual Input)")
        # Try to identify different pods in the text
        lines = log_text.split('\n')
        pods_logs = defaultdict(list)
        current_pod = None
        
        for line in lines:
            if not line.strip():
                continue
                
            # Try to identify pod from line content
            pod_match = re.search(r'weaviate-(\d+)', line)
            if pod_match:
                current_pod = f"weaviate-{pod_match.group(1)}"
            
            # If no pod identified and we haven't set a default, use weaviate-0
            if current_pod is None:
                current_pod = "weaviate-0"
            
            pods_logs[current_pod].append(line)
        
        # Convert back to strings
        result = {}
        for pod, lines in pods_logs.items():
            if lines:  # Only add pods that have content
                result[pod] = '\n'.join(lines)
            
        return result

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
