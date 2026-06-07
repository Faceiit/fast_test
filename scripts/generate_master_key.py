from pathlib import Path

from cryptography.fernet import Fernet


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SECRETS_DIR = PROJECT_ROOT / "secrets"
MASTER_KEY_FILE = SECRETS_DIR / "sms_master_key"


def main() -> None:
    SECRETS_DIR.mkdir(exist_ok=True)

    if MASTER_KEY_FILE.exists():
        raise FileExistsError(
            f"Master key already exists: {MASTER_KEY_FILE}\n"
            "Delete it manually only if you are sure you do not need old encrypted secrets."
        )

    MASTER_KEY_FILE.write_text(
        Fernet.generate_key().decode("utf-8") + "\n",
        encoding="utf-8",
    )

    print(f"Master key written to: {MASTER_KEY_FILE}")


if __name__ == "__main__":
    main()
