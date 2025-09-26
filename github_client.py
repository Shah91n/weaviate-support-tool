import requests
import base64
from typing import Optional, Dict, Any


class GitHubClient:
    """Client for fetching code from GitHub"""
    
    def __init__(self, token: Optional[str] = None):
        self.base_url = "https://api.github.com"
        self.headers = {'Accept': 'application/vnd.github.v3+json'}
        if token:
            self.headers['Authorization'] = f'token {token}'
        self._cache = {}
    
    def fetch_code_context(self, file_path: str, line_number: int, context_lines: int = 30) -> Optional[Dict[str, Any]]:
        """Fetch code context around a specific line"""
        try:
            # Convert to GitHub path
            github_path = self.convert_to_github_path(file_path)
            
            # Check cache
            if github_path in self._cache:
                file_content = self._cache[github_path]
            else:
                # Fetch from GitHub
                file_content = self.fetch_file(github_path)
                if not file_content:
                    return None
                self._cache[github_path] = file_content
            
            # Extract context
            lines = file_content.split('\n')
            start_line = max(1, line_number - context_lines)
            end_line = min(len(lines), line_number + context_lines)
            
            return {
                'content': file_content,
                'lines': lines[start_line-1:end_line],
                'start_line': start_line,
                'end_line': end_line,
                'panic_line': line_number
            }
            
        except:
            return None
    
    def convert_to_github_path(self, file_path: str) -> str:
        """Convert internal file path to GitHub path"""
        prefixes = [
            '/go/src/github.com/weaviate/weaviate/',
            'github.com/weaviate/weaviate/',
            '/workspace/',
            '/app/',
        ]
        
        result = file_path
        for prefix in prefixes:
            if result.startswith(prefix):
                result = result[len(prefix):]
                break
        
        if 'weaviate/weaviate/' in result:
            parts = result.split('weaviate/weaviate/')
            result = parts[-1]
        
        return result
    
    def fetch_file(self, path: str) -> Optional[str]:
        """Fetch file content from GitHub"""
        url = f"{self.base_url}/repos/weaviate/weaviate/contents/{path}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'content' in data:
                    return base64.b64decode(data['content']).decode('utf-8')
        except:
            pass
        
        return None