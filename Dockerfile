FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0
COPY app ./app
# Run unprivileged, with a writable directory only for the database.
RUN useradd --create-home appuser && mkdir /data && chown appuser /data
USER appuser
ENV DB_PATH=/data/auth.db
EXPOSE 8000
# JWT_SECRET is passed at run time so it is never baked into an image layer.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app.main:create_app()"]
