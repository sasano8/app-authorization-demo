FROM ghcr.io/astral-sh/uv:0.12.19 AS uv
FROM python:3.14-slim
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock .python-version ./
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
RUN uv sync --locked --no-dev --no-cache && useradd --uid 10001 --create-home app
COPY app ./app
USER 10001
ENV PORT=8080 PATH="/app/.venv/bin:$PATH"
EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port \"${PORT}\""]
