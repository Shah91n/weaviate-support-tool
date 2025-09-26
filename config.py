import os
from dotenv import load_dotenv

load_dotenv()

# Optional GitHub token for higher rate limits
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")