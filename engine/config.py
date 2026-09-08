import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print(
        "[CONFIG] dotenv not installed, "
        "using system environment variables"
    )

ABUSE_KEY = os.getenv("ABUSE_KEY")
VT_KEY = os.getenv("VT_KEY")

if not ABUSE_KEY:
    print("[CONFIG] WARNING: ABUSE_KEY not set")

if not VT_KEY:
    print("[CONFIG] WARNING: VT_KEY not set")