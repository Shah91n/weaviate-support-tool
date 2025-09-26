import re
from typing import Optional
from extractors.configuration_extractor import ConfigurationExtractor
from dataclasses import dataclass
from typing import Dict, List, Optional
import pandas as pd


@dataclass
class ConfigurationInfo:
    """Configuration information from kubectl describe"""
    name: str
    image: str
    ports: List[str]
    cpu_limit: str
    cpu_request: str
    memory_limit: str
    memory_request: str
    environment: Dict[str, str]


@dataclass
class MemoryAnalysis:
    """Memory analysis results"""
    gomemlimit_gib: float
    memory_limit_gib: float
    memory_request_gib: float
    current_ratio: float
    recommended_gomemlimit_gib: float
    recommended_ratio: float
    analysis: str
    recommendation: str


class ConfigurationAnalyzer:
    """Analyzes Weaviate configuration from kubectl describe output"""

    def __init__(self):
        self.pod_info = {}
        self.configuration = []
        self.extractor = ConfigurationExtractor()
    
    def analyze_from_cluster(self, cluster_id: str, pod_name: str) -> Optional[ConfigurationInfo]:
        """Analyze configuration from kubectl describe pod output"""
        print(f"Analyzing configuration for cluster: {cluster_id}, pod: {pod_name}")
        try:
            # Connect and describe pod
            self.extractor.connect_to_cluster(cluster_id)
            describe_text = self.extractor.describe_pod(pod_name)
            return self.analyze_from_text(describe_text)
        except Exception as e:
            raise Exception(f"Failed to analyze configuration: {str(e)}")
    
    def analyze_from_text(self, describe_text: str) -> Optional[ConfigurationInfo]:
        """Analyze configuration from kubectl describe text output"""
        print("Analyzing configuration from describe output...")
        try:
            # Find the main weaviate configuration section
            config_section = self._extract_weaviate_configuration_section(describe_text)
            if not config_section:
                return None
            
            # Extract configuration information
            config_info = self._parse_configuration_info(config_section)
            return config_info

        except Exception as e:
            raise Exception(f"Failed to parse configuration info: {str(e)}")

    def _extract_weaviate_configuration_section(self, text: str) -> Optional[str]:
        """Extract the weaviate configuration section from describe output"""
        print("Extracting weaviate configuration section...")
        lines = text.split('\n')
        config_section = []
        in_config = False
        last_indent = 0
        current_component = ""

        # Look for container and configuration sections
        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue
            
            # Get the indent level of the current line
            indent = len(line) - len(line.lstrip())

            # Check if we're entering a config section
            if line.strip() == "Configuration:":
                in_config = True
                continue
                
            # Look for the start of container sections
            if line.lstrip().startswith("Container:") and "weaviate" in line.lower():
                current_component = "weaviate"
                continue
            elif line.lstrip().startswith("Container:"):
                current_component = "other"
                continue
            
            # Once we're in config and find weaviate content, start collecting
            if in_config and (current_component == "weaviate" or "weaviate" in line.lower()):
                if not config_section:
                    # If this is our first line, set initial indent
                    last_indent = indent
                    config_section.append(line)
                else:
                    # Check if we're still in the same section
                    if indent >= last_indent or not line.strip():
                        config_section.append(line)
                    else:
                        # Lower indent could mean we're done
                        # But check if it's just a continuation of the weaviate section
                        if any(weaviate_term in line.lower() for weaviate_term in [
                            "weaviate", "memory", "cpu", "ports", "environment", "mounts", "volumes"
                        ]):
                            config_section.append(line)
                            last_indent = indent
                        else:
                            break

        if config_section:
            return '\n'.join(config_section)
                    
        # Fallback: try to find any weaviate-related configuration
        found_lines = []
        for i, line in enumerate(lines):
            if "weaviate" in line.lower():
                # Include context lines
                start = max(0, i - 5)
                end = min(len(lines), i + 15)
                context = lines[start:end]
                found_lines.extend(context)
        
        return '\n'.join(found_lines) if found_lines else None
    
    def _parse_configuration_info(self, config_section: str) -> ConfigurationInfo:
        """Parse configuration information from the weaviate configuration section"""
        print("Parsing configuration information...")

        lines = config_section.split('\n')

        # Initialize values
        name = "weaviate"
        image = ""
        ports = []
        cpu_limit = ""
        cpu_request = ""
        memory_limit = ""
        memory_request = ""
        environment = {}
        
        # Parse each line
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            if line.startswith("Image:"):
                image = line.replace("Image:", "").strip()
            
            elif line.startswith("Ports:"):
                # Extract ports from this line and potentially next lines
                ports_text = line.replace("Ports:", "").strip()
                if ports_text:
                    ports.append(ports_text)
                # Check next lines for additional ports
                j = i + 1
                while j < len(lines) and lines[j].startswith("       "):
                    ports.append(lines[j].strip().rstrip(','))
                    j += 1
            
            elif line.startswith("Command:"):
                # Extract command arguments for timeouts
                j = i + 1
                while j < len(lines) and (lines[j].startswith("      ") or lines[j].startswith("    Args:")):
                    if lines[j].strip().startswith("Args:"):
                        # Found Args section, extract timeout values
                        k = j + 1
                        while k < len(lines) and lines[k].startswith("      "):
                            arg_line = lines[k].strip()
                            if "--read-timeout" in arg_line:
                                environment["READ_TIMEOUT"] = arg_line
                            elif "--write-timeout" in arg_line:
                                environment["WRITE_TIMEOUT"] = arg_line
                            elif "--config-file" in arg_line:
                                environment["CONFIG_FILE"] = arg_line
                            k += 1
                        break
                    j += 1
            
            elif line.startswith("Limits:"):
                # Parse limits section
                j = i + 1
                while j < len(lines) and lines[j].startswith("      "):
                    limit_line = lines[j].strip()
                    if limit_line.startswith("cpu:"):
                        cpu_limit = limit_line.replace("cpu:", "").strip()
                    elif limit_line.startswith("memory:"):
                        memory_limit = limit_line.replace("memory:", "").strip()
                    j += 1
            
            elif line.startswith("Requests:"):
                # Parse requests section
                j = i + 1
                while j < len(lines) and lines[j].startswith("      "):
                    request_line = lines[j].strip()
                    if request_line.startswith("cpu:"):
                        cpu_request = request_line.replace("cpu:", "").strip()
                    elif request_line.startswith("memory:"):
                        memory_request = request_line.replace("memory:", "").strip()
                    j += 1
            
            elif line.startswith("Environment:"):
                # Parse environment variables
                j = i + 1
                while j < len(lines) and lines[j].startswith("      "):
                    env_line = lines[j].strip()
                    if ':' in env_line:
                        # Handle different formats
                        if env_line.count(':') >= 2:
                            # Format: KEY: value (source)
                            parts = env_line.split(':', 2)
                            key = parts[0].strip()
                            value = parts[1].strip()
                            # Remove source info if present
                            if '(' in value:
                                value = value.split('(')[0].strip()
                            environment[key] = value
                        else:
                            # Simple KEY: value format
                            key, value = env_line.split(':', 1)
                            environment[key.strip()] = value.strip()
                    j += 1
            
            i += 1
        
        return ConfigurationInfo(
            name=name,
            image=image,
            ports=ports,
            cpu_limit=cpu_limit,
            cpu_request=cpu_request,
            memory_limit=memory_limit,
            memory_request=memory_request,
            environment=environment
        )
    
    def analyze_memory_configuration(self, config_info: ConfigurationInfo) -> MemoryAnalysis:
        """Analyze GOMEMLIMIT vs memory limits and provide recommendations"""
        print("Analyzing memory configuration...")
        # Extract GOMEMLIMIT
        gomemlimit_raw = config_info.environment.get('GOMEMLIMIT', '0')
        gomemlimit_gib = self._parse_memory_to_gib(gomemlimit_raw)
        
        # Extract memory limits/requests
        memory_limit_gib = self._parse_memory_to_gib(config_info.memory_limit)
        memory_request_gib = self._parse_memory_to_gib(config_info.memory_request)
        
        # Calculate current ratio
        current_ratio = (gomemlimit_gib / memory_limit_gib * 100) if memory_limit_gib > 0 else 0
        
        # Determine recommendation based on ratio
        # Target range is 70-80%
        if current_ratio < 60:
            recommended_ratio = 70.0  # Start at the lower end
            status = "INCREASE RECOMMENDED"
            explanation = ("GOMEMLIMIT is too low. Go garbage collector will be aggressive, "
                         "causing frequent GC cycles and poor memory utilization.")
        elif current_ratio < 70:
            recommended_ratio = 70.0  # Bring up to minimum optimal
            status = "MINOR INCREASE SUGGESTED"
            explanation = ("GOMEMLIMIT could be increased for optimal performance. "
                         "Current setting is below the recommended range of 70-80%.")
        elif current_ratio <= 80:
            recommended_ratio = current_ratio  # Already in optimal range
            status = "OPTIMAL RANGE"
            explanation = ("GOMEMLIMIT is in the optimal range (70-80%). "
                         "Good balance between app memory and OS cache.")
        else:
            recommended_ratio = 80.0  # Cap at maximum recommended
            status = "DECREASE RECOMMENDED"
            explanation = ("GOMEMLIMIT is above the recommended maximum of 80%. "
                         "This leaves insufficient memory for OS caching and can hurt disk I/O performance.")
        
        recommended_gomemlimit_gib = memory_limit_gib * (recommended_ratio / 100)
        
        # Create detailed analysis
        analysis = f"""
Current Configuration:
- Memory Limit: {memory_limit_gib:.1f} GiB
- Memory Request: {memory_request_gib:.1f} GiB  
- GOMEMLIMIT: {gomemlimit_gib:.1f} GiB ({current_ratio:.1f}% of limit)

Analysis: {explanation}

Recommendation:
- Set GOMEMLIMIT to {recommended_gomemlimit_gib:.0f}GiB ({recommended_ratio:.0f}% of limit)
- This leaves {memory_limit_gib - recommended_gomemlimit_gib:.0f}GiB for OS cache and overhead
        """.strip()
        
        return MemoryAnalysis(
            gomemlimit_gib=gomemlimit_gib,
            memory_limit_gib=memory_limit_gib,
            memory_request_gib=memory_request_gib,
            current_ratio=current_ratio,
            recommended_gomemlimit_gib=recommended_gomemlimit_gib,
            recommended_ratio=recommended_ratio,
            analysis=analysis,
            recommendation=status
        )
    
    def _parse_memory_to_gib(self, memory_str: str) -> float:
        """Convert memory string to GiB (e.g., '390Gi' -> 390.0, '347400MiB' -> 339.3)"""
        print("Parsing memory string to GiB...")
        if not memory_str or memory_str == '0':
            return 0.0
        
        memory_str = memory_str.strip()
        
        # Remove any non-alphanumeric characters except for the unit
        memory_str = re.sub(r'[^\d\w.]', '', memory_str)
        
        # Parse different units
        if memory_str.endswith('Gi') or memory_str.endswith('GiB'):
            return float(re.sub(r'[^\d.]', '', memory_str))
        elif memory_str.endswith('Mi') or memory_str.endswith('MiB'):
            return float(re.sub(r'[^\d.]', '', memory_str)) / 1024.0
        elif memory_str.endswith('Ki') or memory_str.endswith('KiB'):
            return float(re.sub(r'[^\d.]', '', memory_str)) / (1024.0 * 1024.0)
        elif memory_str.endswith('G'):
            return float(re.sub(r'[^\d.]', '', memory_str)) * 0.9313  # GB to GiB
        elif memory_str.endswith('M'):
            return float(re.sub(r'[^\d.]', '', memory_str)) * 0.9313 / 1024.0  # MB to GiB
        else:
            # Assume bytes
            try:
                return float(memory_str) / (1024.0 ** 3)
            except:
                return 0.0

    def create_summary_dataframe(self, config_info: ConfigurationInfo) -> pd.DataFrame:
        """Create a summary DataFrame of configuration"""
        print("Creating summary DataFrame...")

        # Basic info
        basic_data = [
            ['Image', config_info.image],
            ['Ports', ', '.join(config_info.ports)],
            ['CPU Limit', config_info.cpu_limit],
            ['CPU Request', config_info.cpu_request],
            ['Memory Limit', config_info.memory_limit],
            ['Memory Request', config_info.memory_request],
        ]
        
        basic_df = pd.DataFrame(basic_data, columns=['Configuration', 'Value'])
        
        # Environment variables
        env_data = [[k, v] for k, v in config_info.environment.items()]
        env_df = pd.DataFrame(env_data, columns=['Environment Variable', 'Value'])
        
        return basic_df, env_df

    def create_essential_dataframe(self, config_info: ConfigurationInfo) -> pd.DataFrame:
        """Create essential configuration DataFrame with most important settings"""
        print("Creating essential configuration DataFrame...")
        # Essential configuration
        essential_data = [
            ['Image', config_info.image],
            ['Memory Limit', config_info.memory_limit],
            ['CPU Limit', config_info.cpu_limit],
            ['Memory Request', config_info.memory_request],
            ['CPU Request', config_info.cpu_request],
            ['GOMEMLIMIT', config_info.environment.get('GOMEMLIMIT', 'Not set')],
            ['Read Timeout', config_info.environment.get('READ_TIMEOUT', 'Not found')],
            ['Write Timeout', config_info.environment.get('WRITE_TIMEOUT', 'Not found')],
        ]
        
        essential_df = pd.DataFrame(essential_data, columns=['Essential Configuration', 'Value'])
        
        return essential_df
