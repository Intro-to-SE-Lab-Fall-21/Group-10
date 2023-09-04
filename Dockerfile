# syntax=docker/dockerfile:1

FROM python:3.11

WORKDIR /app

COPY requirements.txt .

RUN pip3 install -r requirements.txt

COPY . /app

EXPOSE 50505

ENTRYPOINT ["gunicorn", "app:app"]
