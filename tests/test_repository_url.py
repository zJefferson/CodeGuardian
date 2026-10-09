import pytest

from app.repository_url import (
    GitHubRepository,
    InvalidRepositoryURLError,
    parse_github_repository_url,
)

# --- URLs válidas -----------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "owner", "name"),
    [
        ("https://github.com/zJefferson/CodeGuardian", "zJefferson", "CodeGuardian"),
        ("https://github.com/zJefferson/CodeGuardian.git", "zJefferson", "CodeGuardian"),
        ("https://github.com/zJefferson/CodeGuardian/", "zJefferson", "CodeGuardian"),
        ("https://github.com/psf/requests", "psf", "requests"),
        ("https://github.com/my-org/repo.name_with-chars", "my-org", "repo.name_with-chars"),
        ("https://GitHub.com/psf/requests", "psf", "requests"),
        ("HTTPS://github.com/psf/requests", "psf", "requests"),
        ("https://github.com:443/psf/requests", "psf", "requests"),
        ("  https://github.com/psf/requests  ", "psf", "requests"),
        ("https://github.com/a/b", "a", "b"),
    ],
)
def test_accepts_valid_github_urls(url: str, owner: str, name: str) -> None:
    repo = parse_github_repository_url(url)

    assert repo == GitHubRepository(owner=owner, name=name)


def test_returns_canonical_url() -> None:
    repo = parse_github_repository_url("https://GitHub.com:443/psf/requests.git/")

    assert repo.url == "https://github.com/psf/requests"


def test_repository_is_immutable() -> None:
    repo = parse_github_repository_url("https://github.com/psf/requests")

    with pytest.raises(ValueError, match="frozen"):
        repo.owner = "other"  # type: ignore[misc]


# --- Esquema, host e porta --------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/psf/requests",
        "git://github.com/psf/requests.git",
        "ssh://git@github.com/psf/requests.git",
        "file:///etc/passwd",
        "ftp://github.com/psf/requests",
        "javascript:alert(1)",
        "//github.com/psf/requests",
        "github.com/psf/requests",
    ],
)
def test_rejects_non_https_schemes(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError, match="HTTPS"):
        parse_github_repository_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://gitlab.com/psf/requests",
        "https://www.github.com/psf/requests",
        "https://api.github.com/repos/psf/requests",
        "https://raw.githubusercontent.com/psf/requests/main/README.md",
        "https://github.com.evil.com/psf/requests",
        "https://evilgithub.com/psf/requests",
        "https://github.com./psf/requests",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://2130706433/psf/requests",
    ],
)
def test_rejects_other_hosts(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError, match="github.com"):
        parse_github_repository_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com:80/psf/requests",
        "https://github.com:8080/psf/requests",
        "https://github.com:22/psf/requests",
    ],
)
def test_rejects_disallowed_ports(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError, match="porta"):
        parse_github_repository_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@github.com/psf/requests",
        "https://ghp_token123@github.com/psf/requests",
        "https://user@github.com/psf/requests",
        "https://github.com@evil.com/psf/requests",
        "https://:@github.com/psf/requests",
    ],
)
def test_rejects_embedded_credentials(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError, match="credenciais"):
        parse_github_repository_url(url)


# --- Tentativas de acesso interno -------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/psf/requests",
        "https://LOCALHOST/psf/requests",
        "https://api.localhost/psf/requests",
    ],
)
def test_rejects_localhost(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError, match="locais"):
        parse_github_repository_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/psf/requests",
        "https://10.0.0.5/psf/requests",
        "https://172.16.0.1/psf/requests",
        "https://192.168.1.1/psf/requests",
        "https://169.254.169.254/latest/meta-data/",
        "https://0.0.0.0/psf/requests",
        "https://140.82.112.3/psf/requests",
        "https://[::1]/psf/requests",
        "https://[fd00::1]/psf/requests",
        "https://[::ffff:127.0.0.1]/psf/requests",
    ],
)
def test_rejects_ip_addresses(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError, match="IP"):
        parse_github_repository_url(url)


# --- Caminho -------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com",
        "https://github.com/",
        "https://github.com/psf",
        "https://github.com/psf/",
        "https://github.com/psf/requests/tree/main",
        "https://github.com/psf/requests/issues/1",
        "https://github.com//requests",
        "https://github.com/psf//requests",
        "https://github.com/psf/requests//",
    ],
)
def test_rejects_unexpected_path_shape(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError):
        parse_github_repository_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/-psf/requests",
        "https://github.com/psf-/requests",
        "https://github.com/ps--f/requests",
        "https://github.com/ps_f/requests",
        "https://github.com/ps.f/requests",
        f"https://github.com/{'a' * 40}/requests",
    ],
)
def test_rejects_invalid_owner(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError, match="usuário ou organização"):
        parse_github_repository_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/psf/..",
        "https://github.com/psf/.",
        "https://github.com/psf/.git",
        "https://github.com/psf/re$quests",
        "https://github.com/psf/re:quests",
        "https://github.com/psf/re;quests",
    ],
)
def test_rejects_invalid_repository_name(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError):
        parse_github_repository_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/psf/%2e%2e",
        "https://github.com/psf%2Frequests/x",
        "https://github.com/psf\\requests",
        "https://github.com/../../etc/passwd",
    ],
)
def test_rejects_encoded_or_traversal_paths(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError):
        parse_github_repository_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/psf/requests?tab=readme",
        "https://github.com/psf/requests?",
        "https://github.com/psf/requests#readme",
    ],
)
def test_rejects_query_and_fragment(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError, match="consulta ou fragmentos"):
        parse_github_repository_url(url)


# --- Entradas malformadas ---------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "not a url",
        "https://",
        "https:///psf/requests",
        "https://[::1/psf/requests",
        "https://github.com:abc/psf/requests",
        "https://github.com:99999/psf/requests",
        "https://github.com/psf/req\nuests",
        "https://github.com/psf/req\tuests",
        "https://github.com/psf/re quests",
        "https://github.com/psf/requests\x00",
        "https://gіthub.com/psf/requests",  # "і" cirílico (homógrafo)
        "https://github.com/" + "a/" + "b" * 300,
    ],
)
def test_rejects_malformed_input(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError):
        parse_github_repository_url(url)


@pytest.mark.parametrize("value", [None, 123, b"https://github.com/psf/requests"])
def test_rejects_non_string_input(value: object) -> None:
    with pytest.raises(InvalidRepositoryURLError, match="texto"):
        parse_github_repository_url(value)  # type: ignore[arg-type]


# --- Mensagens de erro seguras ----------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://user:supersecret@github.com/psf/requests",
        "https://supersecret@evil.com/psf/requests",
        "https://github.com/psf/requests?token=supersecret",
        "http://github.com/psf/supersecret",
        "https://evil.com/supersecret/requests",
    ],
)
def test_error_message_does_not_echo_input(url: str) -> None:
    with pytest.raises(InvalidRepositoryURLError) as exc_info:
        parse_github_repository_url(url)

    assert "supersecret" not in str(exc_info.value)
    assert "supersecret" not in exc_info.value.message
