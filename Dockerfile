FROM python:3.11-slim

WORKDIR /app

COPY Packet_analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY Packet_analyzer/ .

EXPOSE 5000

CMD ["python", "api_server.py", "--model", "models/cic_rf_model.pkl"]
