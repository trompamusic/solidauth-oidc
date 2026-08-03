FROM python:3.13

ENV UV_LINK_MODE=copy \
  UV_COMPILE_BYTECODE=1 \
  UV_PYTHON_DOWNLOADS=never \
  UV_PYTHON=3.13 \
  UV_PROJECT_ENVIRONMENT=/opt/venv \
  PATH="/opt/venv/bin:$PATH"

COPY --from=ghcr.io/astral-sh/uv:0.9.15 /uv /uvx /bin/

RUN mkdir /code
WORKDIR /code

COPY pyproject.toml uv.lock /code
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-install-project

COPY . /code
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev

CMD ["flask", "run"]
