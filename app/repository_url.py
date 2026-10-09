"""Validação de URLs de repositórios Git públicos.

A validação usa lista de permissões: apenas ``https://github.com/<owner>/<repo>``
é aceito. Estar no GitHub não torna o repositório confiável; esta etapa apenas
garante que a URL aponta para o destino esperado e não para recursos internos.

As mensagens de erro são fixas e nunca reproduzem a entrada, que pode conter
credenciais ou outros dados sensíveis.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

ALLOWED_SCHEME = "https"
ALLOWED_HOST = "github.com"
ALLOWED_PORTS = frozenset({None, 443})
MAX_URL_LENGTH = 256

# Regras de nomes do GitHub: usuário/organização com até 39 caracteres,
# alfanuméricos e hífens simples, sem hífen no início ou no fim.
_OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")
_REPO_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,100}")
_GIT_SUFFIX = ".git"


class InvalidRepositoryURLError(ValueError):
    """URL de repositório rejeitada. A mensagem é segura para exibir ao usuário."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class GitHubRepository(BaseModel):
    """Repositório do GitHub identificado a partir de uma URL validada."""

    model_config = ConfigDict(frozen=True)

    owner: str
    name: str

    @property
    def url(self) -> str:
        """URL canônica, sem credenciais, porta, query ou fragmento."""
        return f"https://{ALLOWED_HOST}/{self.owner}/{self.name}"


def parse_github_repository_url(raw: str) -> GitHubRepository:
    """Valida ``raw`` e retorna o repositório correspondente.

    Raises:
        InvalidRepositoryURLError: se a URL não for um repositório público
            do GitHub no formato ``https://github.com/<owner>/<repo>``.
    """
    if not isinstance(raw, str):
        raise InvalidRepositoryURLError("A URL do repositório deve ser um texto.")

    candidate = raw.strip()
    if not candidate:
        raise InvalidRepositoryURLError("A URL do repositório é obrigatória.")
    if len(candidate) > MAX_URL_LENGTH:
        raise InvalidRepositoryURLError(
            f"A URL do repositório excede o limite de {MAX_URL_LENGTH} caracteres."
        )
    # Bloqueia caracteres não ASCII (homógrafos como "gіthub.com" com "і" cirílico),
    # espaços e caracteres de controle no meio da URL.
    if not candidate.isascii() or any(
        ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate
    ):
        raise InvalidRepositoryURLError("A URL contém caracteres não permitidos.")

    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError:
        raise InvalidRepositoryURLError("A URL do repositório está malformada.") from None

    if parts.scheme != ALLOWED_SCHEME:
        raise InvalidRepositoryURLError("Apenas URLs HTTPS são permitidas.")
    if not parts.netloc:
        raise InvalidRepositoryURLError("A URL do repositório está malformada.")
    if "@" in parts.netloc:
        raise InvalidRepositoryURLError("A URL não pode conter credenciais.")

    host = parts.hostname or ""
    _reject_internal_host(host)
    if host != ALLOWED_HOST:
        raise InvalidRepositoryURLError(
            f"Apenas repositórios hospedados em {ALLOWED_HOST} são permitidos."
        )
    if port not in ALLOWED_PORTS:
        raise InvalidRepositoryURLError("A porta informada não é permitida.")

    if "?" in candidate or "#" in candidate:
        raise InvalidRepositoryURLError(
            "A URL não pode conter parâmetros de consulta ou fragmentos."
        )

    owner, name = _parse_path(parts.path)
    return GitHubRepository(owner=owner, name=name)


def _reject_internal_host(host: str) -> None:
    """Gera mensagens específicas para hosts locais, privados ou endereços IP."""
    if not host:
        raise InvalidRepositoryURLError("A URL do repositório está malformada.")
    if host == "localhost" or host.endswith(".localhost"):
        raise InvalidRepositoryURLError("Endereços locais não são permitidos.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return
    raise InvalidRepositoryURLError("Endereços IP não são permitidos; use o domínio github.com.")


def _parse_path(path: str) -> tuple[str, str]:
    """Extrai ``owner`` e ``repo`` de ``/<owner>/<repo>[.git][/]``."""
    expected = "O caminho deve seguir o formato /<usuário>/<repositório>."
    if "%" in path or "\\" in path:
        raise InvalidRepositoryURLError(
            "O caminho contém caracteres codificados ou não permitidos."
        )

    if path.endswith("/"):
        path = path[:-1]
    segments = path.split("/")
    # path começa com "/", então o primeiro segmento é vazio.
    if len(segments) != 3 or segments[0] != "":
        raise InvalidRepositoryURLError(expected)

    owner, name = segments[1], segments[2]
    if name.endswith(_GIT_SUFFIX):
        name = name[: -len(_GIT_SUFFIX)]

    if not _OWNER_PATTERN.fullmatch(owner):
        raise InvalidRepositoryURLError("O nome do usuário ou organização é inválido.")
    if not _REPO_PATTERN.fullmatch(name) or name in {".", ".."}:
        raise InvalidRepositoryURLError("O nome do repositório é inválido.")
    return owner, name
