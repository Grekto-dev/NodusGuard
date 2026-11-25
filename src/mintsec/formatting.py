"""Utilitários de formatação de datas locais absolutas e tamanhos."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import re
import subprocess


def now_iso() -> str:
    """Retorna timestamp ISO-8601 no fuso horário local com precisão de segundos."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_timestamp(value: str | datetime | None) -> datetime | None:
    """Converte string ISO-8601 ou datetime para horário local."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return dt.astimezone()


def format_local_datetime(value: str | datetime | None) -> str:
    """Formata data e hora locais absolutas no padrão '21/11/2026 às 14:32'."""
    dt = parse_timestamp(value)
    if dt is None:
        return "Sem registro"
    return f"{dt:%d/%m/%Y} às {dt:%H:%M}"


def format_confirmed_at(value: str | datetime | None) -> str:
    """Formata evidência temporal no padrão 'Confirmado em DD/MM/AAAA às HH:MM'."""
    dt = parse_timestamp(value)
    if dt is None:
        return "Sem confirmação recente"
    return f"Confirmado em {dt:%d/%m/%Y} às {dt:%H:%M}"


def format_bytes(size: int) -> str:
    """Formata quantidade de bytes usando unidades binárias legíveis."""
    if size < 1024:
        return f"{size} B"
    units = ("KiB", "MiB", "GiB", "TiB")
    value = float(size)
    for unit in units:
        value /= 1024.0
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.1f} {unit}".replace(".", ",")
    return f"{size} B"


def utc_now_iso() -> str:
    """Retorna timestamp UTC ISO-8601 para comparações determinísticas."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_DBUS_ERR_PREFIX_RE = re.compile(r"^(?:dbus\.exceptions\.DBusException:\s*)?(?:org\.[a-zA-Z0-9_.]+\s*:\s*)")


def format_error_message(exc: Exception) -> str:
    """Extrai mensagem legível de exceções locais ou D-Bus sem prefixos internos."""
    getter = getattr(exc, "get_dbus_message", None)
    if callable(getter):
        msg = str(getter() or "").strip()
        if msg:
            return msg
    raw = str(exc).strip()
    if raw:
        cleaned = _DBUS_ERR_PREFIX_RE.sub("", raw).strip()
        return cleaned or raw
    return exc.__class__.__name__


@dataclass(frozen=True)
class ErrorReport:
    """Diagnóstico estruturado de falhas com causa provável, orientação e detalhe técnico."""

    summary: str
    cause: str
    suggestion: str
    technical_details: str
    error_code: str = "generic"
    operation: str = ""


def _dbus_name(exc: object) -> str:
    getter = getattr(exc, "get_dbus_name", None)
    if callable(getter):
        try:
            return str(getter() or "").strip()
        except Exception:
            return ""
    return ""


def build_error_report(
    error: Exception | str,
    *,
    operation: str = "",
    lang: str = "en",
) -> ErrorReport:
    """Constrói diagnóstico claro explicando o que ocorreu e como resolver."""
    is_pt = str(lang or "en").lower().startswith("pt")
    if isinstance(error, Exception):
        msg = format_error_message(error)
        exc_type = error.__class__.__name__
        dbus_name = _dbus_name(error)
        raw_full = str(error).strip()
        errno_val = getattr(error, "errno", None)
    else:
        msg = str(error or "").strip() or ("Unknown error" if not is_pt else "Erro desconhecido")
        exc_type = "RuntimeError"
        dbus_name = ""
        raw_full = msg
        errno_val = None

    hay = f"{exc_type} {dbus_name} {msg} {raw_full}".lower()
    tech_parts = []
    if operation:
        tech_parts.append(f"Operation: {operation}")
    tech_parts.append(f"Type: {exc_type}")
    if dbus_name:
        tech_parts.append(f"D-Bus: {dbus_name}")
    if errno_val is not None:
        tech_parts.append(f"Errno: {errno_val}")
    tech_parts.append(f"Detail: {raw_full or msg}")
    tech = "\n".join(tech_parts)

    # 1. Autenticação / Polkit cancelada ou negada
    if (
        exc_type == "AuthorizationError"
        or "accessdenied" in hay
        or "authfailed" in hay
        or "polkit" in hay
        or "not authorized" in hay
        or "dismissed" in hay
        or "não autorizado" in hay
        or "cancelad" in hay
    ):
        return ErrorReport(
            summary=msg,
            cause=(
                "A autorização administrativa (Polkit) foi negada, cancelada ou expirou antes de concluir a ação."
                if is_pt
                else "Administrator authorization (Polkit) was denied, cancelled, or timed out before completing the action."
            ),
            suggestion=(
                "Tente novamente e digite sua senha de administrador quando a janela de autenticação do sistema aparecer."
                if is_pt
                else "Retry the action and enter your administrator password when the system authentication prompt appears."
            ),
            technical_details=tech,
            error_code="auth_denied",
            operation=operation,
        )

    # 2. Permissão insuficiente / precisa root
    if (
        isinstance(error, PermissionError)
        or errno_val in (errno.EACCES, errno.EPERM)
        or "superusuário" in hay
        or "superuser" in hay
        or "permission denied" in hay
        or "permissão negada" in hay
    ):
        return ErrorReport(
            summary=msg,
            cause=(
                "A operação exigiu privilégios de sistema ou permissão de escrita em um recurso protegido."
                if is_pt
                else "The operation required elevated system privileges or write access to a protected resource."
            ),
            suggestion=(
                "Verifique se o serviço mint-security-daemon está ativo ('systemctl status mint-security-daemon') e confirme o prompt administrativo."
                if is_pt
                else "Check that the mint-security-daemon service is running ('systemctl status mint-security-daemon') and approve the administrator prompt."
            ),
            technical_details=tech,
            error_code="permission_denied",
            operation=operation,
        )

    # 3. Daemon D-Bus indisponível
    if (
        "serviceunknown" in hay
        or "namehasnoowner" in hay
        or "noreply" in hay
        or "mint-security-daemon" in hay
        or "org.mintsecurity" in dbus_name.lower()
    ):
        return ErrorReport(
            summary=msg,
            cause=(
                "Não foi possível comunicar com o serviço de sistema do NodusGuard no barramento D-Bus."
                if is_pt
                else "Could not communicate with the NodusGuard system daemon over D-Bus."
            ),
            suggestion=(
                "Verifique se os pacotes do NodusGuard foram instalados corretamente e se o serviço 'mint-security-daemon' responde sem falhas."
                if is_pt
                else "Verify that the NodusGuard packages are properly installed and that 'mint-security-daemon' is healthy."
            ),
            technical_details=tech,
            error_code="dbus_unavailable",
            operation=operation,
        )

    # 4. Timeout
    if (
        isinstance(error, (TimeoutError, subprocess.TimeoutExpired))
        or "timedout" in hay
        or "timed out" in hay
        or "tempo esgotado" in hay
    ):
        return ErrorReport(
            summary=msg,
            cause=(
                "O comando ou serviço demorou mais que o limite esperado para responder."
                if is_pt
                else "The command or system service took longer than expected to respond."
            ),
            suggestion=(
                "Verifique sua conexão ou carga do sistema, aguarde alguns instantes e tente novamente."
                if is_pt
                else "Check your network connection or system load, wait a moment, and try again."
            ),
            technical_details=tech,
            error_code="timeout",
            operation=operation,
        )

    # 5. FreshClam / rede / DNS
    if (
        "locked by another process" in hay
        or "freshclam" in hay
        or "can't query" in hay
        or "name resolution" in hay
        or "network is unreachable" in hay
        or "connection refused" in hay
        or "could not resolve" in hay
        or isinstance(error, ConnectionError)
    ):
        is_lock = "locked by another process" in hay
        return ErrorReport(
            summary=msg,
            cause=(
                "O banco de vírus já está sendo atualizado por outro processo do FreshClam em segundo plano."
                if is_lock and is_pt
                else "Another background FreshClam process currently holds the virus database lock."
                if is_lock
                else "Falha de conexão ou DNS ao tentar baixar atualizações pela rede."
                if is_pt
                else "Network or DNS error while trying to fetch updates online."
            ),
            suggestion=(
                "Aguarde cerca de 1 minuto até a atualização em segundo plano terminar e verifique os logs."
                if is_lock and is_pt
                else "Wait about a minute for the background update to finish, then try again."
                if is_lock
                else "Confira sua conexão com a internet ou configuração de DNS/VPN e tente novamente."
                if is_pt
                else "Check your internet connection or DNS/VPN settings and retry."
            ),
            technical_details=tech,
            error_code="network_or_freshclam",
            operation=operation,
        )

    # 6. Arquivo ou pacote ausente
    if (
        isinstance(error, FileNotFoundError)
        or errno_val == errno.ENOENT
        or "not found" in hay
        or "não encontrado" in hay
        or "no such file" in hay
    ):
        return ErrorReport(
            summary=msg,
            cause=(
                "Um programa auxiliar, pacote ou arquivo necessário não foi encontrado neste sistema."
                if is_pt
                else "A required helper binary, package, or file could not be found on this system."
            ),
            suggestion=(
                "Confirme se o pacote da proteção correspondente está instalado em Proteções e tente novamente."
                if is_pt
                else "Confirm that the corresponding protection package is installed on the Protections page and try again."
            ),
            technical_details=tech,
            error_code="not_found",
            operation=operation,
        )

    # 7. Disco cheio ou somente leitura
    if errno_val in (errno.ENOSPC, errno.EROFS) or "no space left" in hay or "read-only file system" in hay:
        return ErrorReport(
            summary=msg,
            cause=(
                "O disco está sem espaço livre ou montado em modo somente leitura."
                if is_pt
                else "The destination disk is out of space or mounted read-only."
            ),
            suggestion=(
                "Libere espaço em disco ou escolha outro destino gravável antes de repetir."
                if is_pt
                else "Free up disk space or pick a writable destination before retrying."
            ),
            technical_details=tech,
            error_code="storage_error",
            operation=operation,
        )

    # 8. Validação / Firewall UFW
    if isinstance(error, ValueError) or "ufw" in hay or "port" in hay or "porta" in hay or "profile" in hay:
        return ErrorReport(
            summary=msg,
            cause=(
                "Os parâmetros informados foram rejeitados ou o mecanismo retornou erro de configuração."
                if is_pt
                else "The supplied parameters were rejected or the underlying engine reported a configuration error."
            ),
            suggestion=(
                "Revise os campos informados (como número de porta, protocolo ou nome do aplicativo) e consulte a aba Logs."
                if is_pt
                else "Review your entered values (such as port numbers, protocol, or app name) and check the Logs tab."
            ),
            technical_details=tech,
            error_code="validation_or_engine",
            operation=operation,
        )

    # 9. Genérico mantendo causa exata
    return ErrorReport(
        summary=msg,
        cause=(
            f"A operação falhou com erro '{exc_type}': {msg}"
            if is_pt
            else f"The operation failed with '{exc_type}': {msg}"
        ),
        suggestion=(
            "Abra Configurações → Logs para consultar o registro completo deste erro antes de tentar novamente."
            if is_pt
            else "Open Settings → Logs to inspect the full record of this error before trying again."
        ),
        technical_details=tech,
        error_code="generic",
        operation=operation,
    )
