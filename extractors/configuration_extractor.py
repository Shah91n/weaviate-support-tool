import subprocess
from typing import List, Tuple

class ConfigurationExtractor:
    """Responsible for connecting to cluster and fetching 'kubectl describe pod' output."""

    def connect_to_cluster(self, cluster_id: str) -> None:
        print(f"Connecting to cluster: {cluster_id}")
        cmd = ["wcs", "cluster", cluster_id, "--kube"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        print(f"Running command for connecting to cluster: {cmd}")
        if result.returncode != 0:
            raise Exception(f"Failed to connect to cluster: {result.stderr}")

    def describe_pod(self, pod_name: str) -> str:
        print(f"Describing pod: {pod_name}")
        cmd = ["kubectl", "describe", "pod", pod_name]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        print(f"Running command for describing pod: {cmd}")
        if result.returncode != 0:
            raise Exception(result.stderr or "kubectl describe failed")
        return result.stdout

    def get_weaviate_pods(self) -> List[str]:
        """Auto-detect available Weaviate pods in the current context."""
        print("Getting Weaviate pods...")
        try:
            # Get pod names using simple -o name format
            cmd = ["kubectl", "get", "pods", "-l", "app=weaviate", "-o", "name"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(result.stderr or "kubectl get pods failed")

            pod_names = []
            for line in result.stdout.strip().split('\n'):
                if line and line.startswith('pod/'):
                    pod_names.append(line[4:])  # Remove 'pod/' prefix
            return pod_names

        except Exception as e:
            print(f"Failed to get Weaviate pods: {str(e)}")
            return []

    def get_pod_details(self) -> List[dict]:
        """Get detailed info about each Weaviate pod including status and resources."""
        print("Getting pod details...")
        try:
            # First get pod names
            pod_names = self.get_weaviate_pods()
            if not pod_names:
                return []
            
            # Then get details for each pod
            pods = []
            for pod_name in pod_names:
                # Get details in JSON format for easier parsing
                cmd = ["kubectl", "get", "pod", pod_name, "-o", "json"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"Warning: Could not get details for pod {pod_name}")
                    continue
                
                import json
                pod_json = json.loads(result.stdout)
                container = pod_json['spec']['containers'][0]  # Main container
                
                pods.append({
                    "name": pod_name,
                    "status": pod_json['status']['phase'],
                    "cpu_request": container['resources'].get('requests', {}).get('cpu', 'N/A'),
                    "cpu_limit": container['resources'].get('limits', {}).get('cpu', 'N/A'),
                    "memory_request": container['resources'].get('requests', {}).get('memory', 'N/A'),
                    "memory_limit": container['resources'].get('limits', {}).get('memory', 'N/A')
                })

            return pods

        except Exception as e:
            print(f"Failed to get pod details: {str(e)}")
            return []
