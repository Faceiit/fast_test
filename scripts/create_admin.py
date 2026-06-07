import argparse
import getpass
import sys

from sqlalchemy import func, select

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models.identity import Principal, PrincipalRole, PrincipalType, Role, User


DEFAULT_ROLES = {
    "admin": "System administrator",
    "developer": "Developer user",
    "auditor": "Audit log reader",
    "service": "Service account role",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Create initial admin user")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=False)
    args = parser.parse_args()

    username = args.username.strip().lower()
    if not username:
        print("Username cannot be empty", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if password is None:
        password = getpass.getpass("Admin password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Passwords do not match", file=sys.stderr)
            sys.exit(1)

    if len(password) < 8:
        print("Password must be at least 8 characters", file=sys.stderr)
        sys.exit(1)

    with SessionLocal() as db:
        try:
            existing_user = db.scalar(
                select(User).where(func.lower(User.username) == username)
            )
            if existing_user is not None:
                print(f"User '{username}' already exists", file=sys.stderr)
                sys.exit(1)

            roles: dict[str, Role] = {}
            for role_name, description in DEFAULT_ROLES.items():
                normalized_role_name = role_name.strip().lower()
                role = db.scalar(
                    select(Role).where(func.lower(Role.name) == normalized_role_name)
                )
                if role is None:
                    role = Role(name=normalized_role_name, description=description)
                    db.add(role)
                    db.flush()
                roles[normalized_role_name] = role

            principal = Principal(
                principal_type=PrincipalType.USER.value,
                display_name=username,
            )
            db.add(principal)
            db.flush()

            user = User(
                principal_id=principal.id,
                username=username,
                password_hash=hash_password(password),
            )
            db.add(user)
            db.add(
                PrincipalRole(
                    principal_id=principal.id,
                    role_id=roles["admin"].id,
                    granted_by=None,
                )
            )
            db.commit()
        except Exception:
            db.rollback()
            raise

    print(f"Admin user '{username}' created successfully")


if __name__ == "__main__":
    main()
