from __future__ import annotations

import argparse
import getpass
import json
import os
import ssl
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


DEFAULT_BASE_URL = "https://127.0.0.1:8443"
API_PREFIX = "/api/v1"

JsonValue = dict[str, Any] | list[Any]


class ApiClientError(Exception):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class FastApiClient:
    base_url: str = DEFAULT_BASE_URL
    access_token: str | None = None
    api_key: str | None = None
    verify_tls: bool = True
    timeout_seconds: int = 15
    _ssl_context: ssl.SSLContext | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        self._refresh_ssl_context()

    def _refresh_ssl_context(self) -> None:
        self._ssl_context = None if self.verify_tls else ssl._create_unverified_context()

    def set_base_url(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def set_verify_tls(self, verify_tls: bool) -> None:
        self.verify_tls = verify_tls
        self._refresh_ssl_context()

    @property
    def auth_state(self) -> str:
        if self.access_token:
            return "Bearer JWT"
        if self.api_key:
            return "X-API-Key"
        return "нет"

    def login(self, username: str, password: str) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"{API_PREFIX}/auth/login",
            body={"username": username, "password": password},
            authenticated=False,
        )
        if not isinstance(response, dict) or "access_token" not in response:
            raise ApiClientError("Сервер не вернул access_token.")

        self.access_token = str(response["access_token"])
        self.api_key = None
        return response

    def use_api_key(self, api_key: str) -> None:
        api_key = api_key.strip()
        if not api_key:
            raise ApiClientError("API-ключ не может быть пустым.")

        self.api_key = api_key
        self.access_token = None

    def logout(self) -> None:
        self.access_token = None
        self.api_key = None

    def me(self) -> dict[str, Any]:
        return self._expect_dict(self._request("GET", f"{API_PREFIX}/auth/me"))

    def health(self) -> dict[str, Any]:
        return self._expect_dict(self._request("GET", "/health", authenticated=False))

    def api_health(self) -> dict[str, Any]:
        return self._expect_dict(self._request("GET", f"{API_PREFIX}/health", authenticated=False))

    def db_health(self) -> dict[str, Any]:
        return self._expect_dict(self._request("GET", f"{API_PREFIX}/health/db", authenticated=False))

    def create_service_account(self, name: str, expires_at: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": name}
        if expires_at:
            payload["expires_at"] = expires_at

        return self._expect_dict(self._request("POST", f"{API_PREFIX}/service-accounts", body=payload))

    def create_secret(
        self,
        path: str,
        value: str,
        description: str | None = None,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"path": path, "value": value}
        if description:
            payload["description"] = description
        if expires_at:
            payload["expires_at"] = expires_at

        return self._expect_dict(self._request("POST", f"{API_PREFIX}/secrets", body=payload))

    def list_secrets(self) -> list[Any]:
        response = self._request("GET", f"{API_PREFIX}/secrets")
        if not isinstance(response, list):
            raise ApiClientError("Ожидался список секретов, но сервер вернул другой JSON.")
        return response

    def read_secret(self, path: str) -> dict[str, Any]:
        safe_path = quote(path.strip(), safe="/._-")
        return self._expect_dict(self._request("GET", f"{API_PREFIX}/secrets/{safe_path}"))

    def rotate_secret(self, path: str, value: str, expires_at: str | None = None) -> dict[str, Any]:
        safe_path = quote(path.strip(), safe="/._-")
        payload: dict[str, Any] = {"value": value}
        if expires_at:
            payload["expires_at"] = expires_at

        return self._expect_dict(
            self._request("POST", f"{API_PREFIX}/secrets/{safe_path}/versions", body=payload)
        )

    def delete_secret(self, path: str) -> None:
        safe_path = quote(path.strip(), safe="/._-")
        self._request("DELETE", f"{API_PREFIX}/secrets/{safe_path}")

    def grant_policy(self, secret_path: str, principal_id: str, capability: str) -> dict[str, Any]:
        return self._expect_dict(
            self._request(
                "POST",
                f"{API_PREFIX}/policies",
                body={
                    "secret_path": secret_path,
                    "principal_id": principal_id,
                    "capability": capability,
                },
            )
        )

    def list_audit_logs(self, limit: int = 100) -> list[Any]:
        response = self._request("GET", f"{API_PREFIX}/audit", query={"limit": limit})
        if not isinstance(response, list):
            raise ApiClientError("Ожидался список audit logs, но сервер вернул другой JSON.")
        return response

    def raw_request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        authenticated: bool = True,
    ) -> JsonValue | dict[str, Any]:
        return self._request(method, path, body=body, authenticated=authenticated)

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        authenticated: bool = True,
    ) -> JsonValue | dict[str, Any]:
        data = None
        headers = {
            "Accept": "application/json",
            "User-Agent": "secret-management-service-menu-client/1.0",
        }

        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if authenticated:
            if self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"
            elif self.api_key:
                headers["X-API-Key"] = self.api_key
            else:
                raise ApiClientError("Сначала выполните авторизацию.")

        full_path = path
        if query:
            full_path = f"{full_path}?{urlencode(query)}"

        request = Request(
            url=f"{self.base_url}{full_path}",
            data=data,
            headers=headers,
            method=method.upper(),
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds, context=self._ssl_context) as response:
                response_body = response.read().decode("utf-8")
        except HTTPError as exc:
            response_body = exc.read().decode("utf-8", errors="replace")
            detail = _extract_error_detail(response_body)
            raise ApiClientError(detail, status_code=exc.code) from exc
        except URLError as exc:
            raise ApiClientError(f"Не удалось подключиться к API: {exc.reason}") from exc
        except TimeoutError as exc:
            raise ApiClientError("Превышено время ожидания ответа API.") from exc
        except ssl.SSLError as exc:
            raise ApiClientError(
                "Ошибка TLS/SSL. Если используете self-signed сертификат, "
                "запустите клиент с --insecure или отключите проверку TLS в настройках. "
                f"Детали: {exc}"
            ) from exc

        if not response_body:
            return {}

        return json.loads(response_body)

    @staticmethod
    def _expect_dict(value: JsonValue | dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ApiClientError("Ожидался JSON-объект, но сервер вернул другой JSON.")
        return value


class Ui:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"

    def __init__(self, color: bool = True, clear_screen: bool = False) -> None:
        self.color = color and sys.stdout.isatty()
        self.clear_screen = clear_screen

    def c(self, text: str, color: str) -> str:
        if not self.color:
            return text
        return f"{color}{text}{self.RESET}"

    def clear(self) -> None:
        if self.clear_screen and sys.stdout.isatty():
            os.system("cls" if os.name == "nt" else "clear")

    def header(self, client: FastApiClient) -> None:
        self.clear()
        width = 78
        print(self.c("╔" + "═" * width + "╗", self.CYAN))
        title = " Secret Management Service — Console Client "
        print(self.c("║", self.CYAN) + self.c(title.center(width), self.BOLD + self.CYAN) + self.c("║", self.CYAN))
        print(self.c("╠" + "═" * width + "╣", self.CYAN))
        print(self.c("║", self.CYAN) + f" API: {client.base_url}".ljust(width) + self.c("║", self.CYAN))
        print(
            self.c("║", self.CYAN)
            + f" Auth: {client.auth_state} | TLS verify: {'on' if client.verify_tls else 'off'}".ljust(width)
            + self.c("║", self.CYAN)
        )
        print(self.c("╚" + "═" * width + "╝", self.CYAN))

    def menu(self, title: str, items: Iterable[tuple[str, str]]) -> None:
        print()
        print(self.c(f"▶ {title}", self.BOLD + self.BLUE))
        for key, label in items:
            print(f"  {self.c(key.rjust(2), self.YELLOW)}  {label}")
        print()

    def ok(self, message: str) -> None:
        print(self.c(f"✓ {message}", self.GREEN))

    def warn(self, message: str) -> None:
        print(self.c(f"! {message}", self.YELLOW))

    def error(self, message: str) -> None:
        print(self.c(f"✗ {message}", self.RED))

    def info(self, message: str) -> None:
        print(self.c(f"• {message}", self.CYAN))


def redraw_after_choice(client: FastApiClient, ui: Ui, choice: str) -> None:
    if choice == "0":
        return

    ui.header(client)


def main() -> None:
    configure_stdio()

    parser = argparse.ArgumentParser(description="Console menu client for Secret Management Service API")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"API URL, default: {DEFAULT_BASE_URL}")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for local self-signed HTTPS.",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    parser.set_defaults(clear_screen=True)
    parser.add_argument(
        "--clear",
        action="store_true",
        dest="clear_screen",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-clear",
        action="store_false",
        dest="clear_screen",
        help="Do not clear screen between menu screens.",
    )
    args = parser.parse_args()

    client = FastApiClient(base_url=args.base_url, verify_tls=not args.insecure)
    ui = Ui(color=not args.no_color, clear_screen=args.clear_screen)

    while True:
        ui.header(client)
        ui.menu(
            "Главное меню",
            [
                ("1", "Авторизация и текущий principal"),
                ("2", "Health checks"),
                ("3", "Service accounts / API keys"),
                ("4", "Secrets"),
                ("5", "Policies"),
                ("6", "Audit logs"),
                ("7", "Настройки клиента"),
                ("8", "Raw HTTP-запрос к API"),
                ("0", "Выход"),
            ],
        )

        choice = ask("Выберите действие")
        try:
            redraw_after_choice(client, ui, choice)
            if choice == "1":
                auth_menu(client, ui)
            elif choice == "2":
                health_menu(client, ui)
            elif choice == "3":
                service_accounts_menu(client, ui)
            elif choice == "4":
                secrets_menu(client, ui)
            elif choice == "5":
                policies_menu(client, ui)
            elif choice == "6":
                audit_menu(client, ui)
            elif choice == "7":
                settings_menu(client, ui)
            elif choice == "8":
                raw_request_menu(client, ui)
            elif choice == "0":
                ui.ok("Выход.")
                return
            else:
                ui.warn("Неизвестный пункт меню.")
                pause()
        except ApiClientError as exc:
            prefix = f"HTTP {exc.status_code}: " if exc.status_code else ""
            ui.error(f"{prefix}{exc}")
            pause()
        except json.JSONDecodeError:
            ui.error("Сервер вернул не JSON-ответ.")
            pause()
        except KeyboardInterrupt:
            print()
            ui.warn("Операция отменена.")
            pause()


def auth_menu(client: FastApiClient, ui: Ui) -> None:
    while True:
        ui.header(client)
        ui.menu(
            "Авторизация",
            [
                ("1", "Войти по username/password → JWT"),
                ("2", "Использовать X-API-Key"),
                ("3", "Показать /auth/me"),
                ("4", "Сбросить авторизацию в клиенте"),
                ("0", "Назад"),
            ],
        )
        choice = ask("Выберите действие")
        redraw_after_choice(client, ui, choice)

        if choice == "1":
            username = ask_required("Username")
            password = getpass.getpass("Password: ")
            response = client.login(username=username, password=password)
            ui.ok("Авторизация успешна.")
            print_json(response, mask_keys={"access_token"})
            pause()
        elif choice == "2":
            api_key = getpass.getpass("API key: ")
            client.use_api_key(api_key)
            ui.ok("API-ключ сохранён в памяти клиента.")
            pause()
        elif choice == "3":
            print_json(client.me())
            pause()
        elif choice == "4":
            client.logout()
            ui.ok("Авторизация очищена.")
            pause()
        elif choice == "0":
            return
        else:
            ui.warn("Неизвестный пункт меню.")
            pause()


def health_menu(client: FastApiClient, ui: Ui) -> None:
    ui.header(client)
    ui.info("Проверяю /health")
    print_json(client.health())
    ui.info("Проверяю /api/v1/health")
    print_json(client.api_health())
    ui.info("Проверяю /api/v1/health/db")
    print_json(client.db_health())
    pause()


def service_accounts_menu(client: FastApiClient, ui: Ui) -> None:
    while True:
        ui.header(client)
        ui.menu(
            "Service accounts",
            [
                ("1", "Создать service account и API key"),
                ("0", "Назад"),
            ],
        )
        choice = ask("Выберите действие")
        redraw_after_choice(client, ui, choice)

        if choice == "1":
            ui.warn("Создание service account доступно пользователю с ролью admin.")
            name = ask_required("Название service account")
            expires_at = ask_optional_datetime("Expires at ISO, например 2026-12-31T23:59:59, или Enter")
            response = client.create_service_account(name=name, expires_at=expires_at)
            ui.ok("Service account создан. Сохраните api_key сейчас — потом он не будет показан.")
            print_json(response)
            pause()
        elif choice == "0":
            return
        else:
            ui.warn("Неизвестный пункт меню.")
            pause()


def secrets_menu(client: FastApiClient, ui: Ui) -> None:
    while True:
        ui.header(client)
        ui.menu(
            "Secrets",
            [
                ("1", "Создать secret"),
                ("2", "Список доступных secrets"),
                ("3", "Прочитать secret value"),
                ("4", "Добавить новую версию / rotate secret"),
                ("5", "Удалить secret"),
                ("0", "Назад"),
            ],
        )
        choice = ask("Выберите действие")
        redraw_after_choice(client, ui, choice)

        if choice == "1":
            path = ask_required("Path, например kv/dev/postgres/password")
            value = getpass.getpass("Secret value: ")
            if not value:
                raise ApiClientError("Secret value не может быть пустым.")
            description = ask("Description, или Enter", default="") or None
            expires_at = ask_optional_datetime("Expires at ISO, например 2026-12-31T23:59:59, или Enter")
            response = client.create_secret(path=path, value=value, description=description, expires_at=expires_at)
            ui.ok("Secret создан.")
            print_json(response)
            pause()

        elif choice == "2":
            secrets = client.list_secrets()
            if not secrets:
                ui.warn("Список пуст.")
            else:
                print_table(
                    secrets,
                    columns=["path", "current_version", "description", "owner_principal_id"],
                )
            pause()

        elif choice == "3":
            path = ask_required("Path секрета")
            response = client.read_secret(path)
            ui.warn("Plaintext value показан только в этом ответе. Не копируйте его в логи.")
            print_json(response)
            pause()

        elif choice == "4":
            path = ask_required("Path секрета")
            value = getpass.getpass("New secret value: ")
            if not value:
                raise ApiClientError("New secret value не может быть пустым.")
            expires_at = ask_optional_datetime("Expires at ISO, например 2026-12-31T23:59:59, или Enter")
            response = client.rotate_secret(path=path, value=value, expires_at=expires_at)
            ui.ok("Secret version добавлена.")
            print_json(response)
            pause()

        elif choice == "5":
            path = ask_required("Path секрета для удаления")
            if confirm(f"Удалить secret '{path}'?"):
                client.delete_secret(path)
                ui.ok("Secret удалён.")
            else:
                ui.warn("Удаление отменено.")
            pause()

        elif choice == "0":
            return
        else:
            ui.warn("Неизвестный пункт меню.")
            pause()


def policies_menu(client: FastApiClient, ui: Ui) -> None:
    capabilities = ["read", "update", "delete", "rotate", "manage_policy"]

    while True:
        ui.header(client)
        ui.menu(
            "Policies",
            [
                ("1", "Выдать доступ к secret"),
                ("0", "Назад"),
            ],
        )
        choice = ask("Выберите действие")
        redraw_after_choice(client, ui, choice)

        if choice == "1":
            secret_path = ask_required("Secret path")
            principal_id = ask_required("Principal UUID, кому выдаём доступ")
            print("Доступные capability:")
            for idx, capability in enumerate(capabilities, start=1):
                print(f"  {idx}. {capability}")
            raw_capability = ask_required("Capability или номер")
            capability = parse_capability(raw_capability, capabilities)
            response = client.grant_policy(
                secret_path=secret_path,
                principal_id=principal_id,
                capability=capability,
            )
            ui.ok("Policy создана.")
            print_json(response)
            pause()
        elif choice == "0":
            return
        else:
            ui.warn("Неизвестный пункт меню.")
            pause()


def audit_menu(client: FastApiClient, ui: Ui) -> None:
    ui.header(client)
    limit = ask_int("Сколько audit logs показать", default=100, minimum=1, maximum=500)
    logs = client.list_audit_logs(limit=limit)
    if not logs:
        ui.warn("Audit log пуст.")
    else:
        print_table(
            logs,
            columns=["created_at", "action", "status", "actor_type", "actor_id", "secret_id"],
        )
        print()
        if confirm("Показать полный JSON audit logs?"):
            print_json(logs)
    pause()


def settings_menu(client: FastApiClient, ui: Ui) -> None:
    while True:
        ui.header(client)
        ui.menu(
            "Настройки клиента",
            [
                ("1", "Изменить base URL"),
                ("2", "Preset: direct FastAPI http://127.0.0.1:8000"),
                ("3", "Preset: Nginx HTTP http://127.0.0.1:8080"),
                ("4", "Preset: Nginx HTTPS https://127.0.0.1:8443"),
                ("5", "Включить/выключить проверку TLS сертификата"),
                ("0", "Назад"),
            ],
        )
        choice = ask("Выберите действие")
        redraw_after_choice(client, ui, choice)

        if choice == "1":
            base_url = ask_required(f"Новый base URL [{client.base_url}]")
            client.set_base_url(base_url)
            ui.ok(f"Base URL изменён: {client.base_url}")
            pause()
        elif choice == "2":
            client.set_base_url("http://127.0.0.1:8000")
            ui.ok(f"Base URL: {client.base_url}")
            pause()
        elif choice == "3":
            client.set_base_url("http://127.0.0.1:8080")
            ui.ok(f"Base URL: {client.base_url}")
            pause()
        elif choice == "4":
            client.set_base_url("https://127.0.0.1:8443")
            client.set_verify_tls(False)
            ui.ok(f"Base URL: {client.base_url}")
            ui.warn("TLS verification отключена для локального self-signed сертификата.")
            pause()
        elif choice == "5":
            client.set_verify_tls(not client.verify_tls)
            ui.ok(f"TLS verification: {'on' if client.verify_tls else 'off'}")
            pause()
        elif choice == "0":
            return
        else:
            ui.warn("Неизвестный пункт меню.")
            pause()


def raw_request_menu(client: FastApiClient, ui: Ui) -> None:
    ui.header(client)
    ui.warn("Raw request нужен для быстрой проверки новых endpoints без переписывания клиента.")
    method = ask_required("HTTP method, например GET/POST/DELETE").upper()
    path = ask_required("Path, например /api/v1/health")
    use_auth = confirm("Добавлять текущую авторизацию?", default=True)
    body: dict[str, Any] | None = None

    if method in {"POST", "PUT", "PATCH"}:
        raw_body = ask("JSON body одной строкой, или Enter для пустого body", default="")
        if raw_body:
            parsed = json.loads(raw_body)
            if not isinstance(parsed, dict):
                raise ApiClientError("Raw body должен быть JSON-объектом.")
            body = parsed

    response = client.raw_request(method=method, path=path, body=body, authenticated=use_auth)
    print_json(response)
    pause()


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    value = input(f"{prompt}{suffix}: ").strip()
    if not value and default is not None:
        return default
    return value


def ask_required(prompt: str) -> str:
    while True:
        value = ask(prompt)
        if value:
            return value
        print("Значение не может быть пустым.")


def ask_optional_datetime(prompt: str) -> str | None:
    value = ask(prompt, default="")
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise ApiClientError("Дата должна быть в ISO-формате, например 2026-12-31T23:59:59.") from exc


def ask_int(prompt: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        raw = ask(prompt, default=str(default))
        try:
            value = int(raw)
        except ValueError:
            print("Введите число.")
            continue
        if not minimum <= value <= maximum:
            print(f"Введите число от {minimum} до {maximum}.")
            continue
        return value


def confirm(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = input(f"{prompt} ({hint}): ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes", "д", "да"}


def pause() -> None:
    input("\nНажмите Enter, чтобы продолжить...")


def parse_capability(raw_value: str, capabilities: list[str]) -> str:
    value = raw_value.strip()
    if value.isdigit():
        index = int(value) - 1
        if 0 <= index < len(capabilities):
            return capabilities[index]
    if value in capabilities:
        return value
    raise ApiClientError(f"Неизвестная capability: {raw_value}")


def print_json(value: Any, mask_keys: set[str] | None = None) -> None:
    if mask_keys:
        value = mask_json(value, mask_keys)
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def mask_json(value: Any, mask_keys: set[str]) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key in mask_keys and isinstance(item, str):
                result[key] = mask_secret(item)
            else:
                result[key] = mask_json(item, mask_keys)
        return result
    if isinstance(value, list):
        return [mask_json(item, mask_keys) for item in value]
    return value


def mask_secret(value: str, visible: int = 8) -> str:
    if len(value) <= visible * 2:
        return "***"
    return f"{value[:visible]}...{value[-visible:]}"


def print_table(rows: list[Any], columns: list[str]) -> None:
    normalized: list[dict[str, Any]] = [row for row in rows if isinstance(row, dict)]
    if not normalized:
        print_json(rows)
        return

    widths: dict[str, int] = {}
    for column in columns:
        values = [stringify_cell(row.get(column)) for row in normalized]
        widths[column] = min(max([len(column), *(len(value) for value in values)]), 42)

    separator = "+" + "+".join("-" * (widths[column] + 2) for column in columns) + "+"
    header = "|" + "|".join(f" {column[:widths[column]].ljust(widths[column])} " for column in columns) + "|"

    print(separator)
    print(header)
    print(separator)
    for row in normalized:
        line = "|" + "|".join(
            f" {trim_cell(stringify_cell(row.get(column)), widths[column]).ljust(widths[column])} "
            for column in columns
        ) + "|"
        print(line)
    print(separator)


def stringify_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def trim_cell(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


def _extract_error_detail(response_body: str) -> str:
    try:
        data = json.loads(response_body)
    except json.JSONDecodeError:
        return response_body or "HTTP request failed"

    detail = data.get("detail") if isinstance(data, dict) else None
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list):
        return json.dumps(detail, ensure_ascii=False)

    return json.dumps(data, ensure_ascii=False)


def configure_stdio() -> None:
    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, stream_name)
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


if __name__ == "__main__":
    main()
