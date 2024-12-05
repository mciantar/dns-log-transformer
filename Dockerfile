FROM python:3.14.0a2

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY app .

ENV PYTHONUNBUFFERED=.

ENTRYPOINT [ "python", "-m", "app.app"]
