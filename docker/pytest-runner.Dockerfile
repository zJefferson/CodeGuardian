# Imagem para a execução isolada de testes (app/test_runner.py).
#
# Contém apenas Python e pytest. Nenhuma dependência dos repositórios analisados é
# instalada, nem aqui nem durante a execução (o container roda sem rede).
#
# Construção (requer rede apenas neste momento; conteúdo confiável):
#   docker build -f docker/pytest-runner.Dockerfile -t codeguardian/pytest-runner:0.1.0 .
#
# Recomendado: fixar a imagem base por digest para builds reproduzíveis. Obtenha o
# digest com "docker buildx imagetools inspect python:3.14-slim" e use
#   FROM python:3.14-slim@sha256:<digest>
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Mesma versão do pytest usada pelo CodeGuardian (requirements.txt).
RUN python -m pip install --no-cache-dir "pytest==9.1.1"

# Usuário sem privilégios (nobody). O CodeGuardian também força --user 65534:65534.
USER 65534:65534
WORKDIR /workspace

CMD ["python", "-m", "pytest", "--version"]
