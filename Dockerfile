FROM python:3.11

WORKDIR /code

COPY requirements.txt .

RUN pip3 install -r requirements.txt

COPY . .
COPY /App .

EXPOSE 5000

ENTRYPOINT ["gunicorn", "app:app"]