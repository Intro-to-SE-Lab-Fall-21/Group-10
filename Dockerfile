# syntax=docker/dockerfile:1

FROM python:3.11

COPY requirements.txt /
RUN pip3 install -r /requirements.txt

COPY . /app
WORKDIR /app

ENTRYPOINT ["./gunicorn_starter.sh"]