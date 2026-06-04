FROM python:3.10.11-slim

WORKDIR /code

RUN apt-get update && apt-get install -y net-tools && rm -rf /var/lib/apt/lists/*

# Install dependencies first to leverage Docker cache
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY . /code/app/

EXPOSE 3006

# Set working directory to app folder so relative paths work correctly
WORKDIR /code/app

# Run Uvicorn directly (standard practice for modern FastAPI)
CMD ["python", "api.py"]