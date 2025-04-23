FROM python:3.11

ENV UV_LINK_MODE=copy \
  UV_COMPILE_BYTECODE=1 \
  UV_PYTHON_DOWNLOADS=never

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN mkdir /code
WORKDIR /code

COPY pyproject.toml uv.lock /code
RUN --mount=type=cache,target=/home/app/.cache/uv uv sync --frozen

COPY . /code

CMD flask run