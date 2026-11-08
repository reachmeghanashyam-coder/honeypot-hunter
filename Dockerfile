FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

# Create non-root sandbox user for strict isolation (Challenge 01 compliance)
RUN groupadd -r investigator && useradd -r -g investigator -m -d /home/investigator investigator

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY backend /app/backend
COPY frontend /app/frontend
COPY tests /app/tests

RUN chown -R investigator:investigator /app

USER investigator

ENV PORT=8000
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
