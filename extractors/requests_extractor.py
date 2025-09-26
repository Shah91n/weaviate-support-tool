import subprocess
from typing import List, Dict, Optional


class RequestsExtractor:
    """Responsible for connecting to cluster and fetching istio-proxy logs for requests analysis."""

    def connect_to_cluster(self, cluster_id: str) -> None:
        """Set kube context for the given cluster using wcs CLI."""
        print(f"Connecting to cluster: {cluster_id}")
        cmd = ["wcs", "cluster", cluster_id, "--kube"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise Exception(f"Failed to connect to cluster: {result.stderr}")

    def list_weaviate_pods(self, provider: Optional[str] = None) -> List[str]:
        """List pod names for weaviate; caller must have kube context already set."""
        print("Listing Weaviate pods...")
        if provider == 'AWS':
            cmd = "kubectl get pods -n gateway -o name"
        else:
            cmd = "kubectl get pods -l app=weaviate -o name"

        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            return []
        return [line[4:] for line in result.stdout.strip().split('\n') if line.startswith('pod/')]

    def fetch_pod_logs(self, pod_name: str, container: str = 'istio-proxy', since_hours: Optional[int] = None, previous: bool = False) -> str:
        """Fetch logs from a pod's container. Returns stdout string or empty on failure."""
        print(f"Fetching logs from pod: {pod_name}, container: {container}, since_hours: {since_hours}, previous: {previous}")
        cmd = ["kubectl", "logs", pod_name, "-c", container]
        if previous:
            cmd.append('--previous')
        if since_hours:
            cmd.append(f"--since={since_hours}h")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return result.stdout
        return ''

    def detect_cloud_provider(self, sample_log: str) -> str:
        """Detect cloud provider by inspecting a log sample."""
        print("Detecting cloud provider...")
        sample = sample_log.lower()
        if 'gcp' in sample:
            return 'GCP'
        if 'aws' in sample:
            return 'AWS'
        return 'Unknown'
