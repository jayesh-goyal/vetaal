FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN pip install -e .
EXPOSE 8888
CMD ["python", "-m", "vetaal.main", "--config", "config/config.yaml"]
