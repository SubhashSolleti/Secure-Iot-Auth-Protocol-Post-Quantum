#!/bin/bash
# Run the dashboard backend using uvicorn

# Ensure we are in the project root
cd "$(dirname "$0")"

# Activate venv if it exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Run uvicorn pointing to the web.backend module
# web.backend:app means module web/backend.py, object app
python -m uvicorn web.backend:app --host 0.0.0.0 --port 8000 --reload
