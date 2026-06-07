import argparse
import getpass
import sys

from sqlalchemy import func, select

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models.identity import Principal, PrincipalRole, Role, User


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
        existing_user = db.scalar(
            select(User).where(func.lower(User.username) == args.username.lower())
        )

        if existing_user is not None:
            print(f"User '{args.username}' already exists", file=sys.stderr)
            sys.exit(1)

        roles: dict[str, Role] = {}

        for role_name, description in DEFAULT_ROLES.items():
            role = db.scalar(select(Role).where(Role.name == role_name))

            if role is None:
                role = Role(name=role_name, description=description)
                db.add(role)
                db.flush()

            roles[role_name] = role

        principal = Principal(
            principal_type="user",
            display_name=args.username,
        )

        db.add(principal)
        db.flush()

        user = User(
            principal_id=principal.id,
            username=args.username,
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

        print(f"Admin user '{args.username}' created successfully")


if __name__ == "__main__":
    main()