"""Dashboard credentials come from the environment; nothing is hardcoded."""
import os

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
REGION = os.environ.get("AWS_REGION", "eu-west-1")
