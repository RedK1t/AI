FROM python:3.10.11-slim

WORKDIR /code

# net-tools for diagnostics; the rest are WeasyPrint runtime deps (PDF report rendering)
RUN apt-get update && apt-get install -y --no-install-recommends \
    net-tools \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libcairo2 libffi-dev shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first to leverage Docker cache
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY . /code/app/

EXPOSE 3006 3007

# Set working directory to app folder so relative paths work correctly
WORKDIR /code/app

# Run Uvicorn directly (standard practice for modern FastAPI)
CMD ["python", "api.py"]