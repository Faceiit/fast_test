from pathlib import Path
from cryptography.fernet import Fernet

Path("secrets").mkdir(exist_ok=True)
Path("../secrets/sms_master_key").write_text(
    Fernet.generate_key().decode("utf-8") + "\n",
    encoding="utf-8",
)