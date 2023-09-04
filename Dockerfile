FROM python:3.11
WORKDIR /App
COPY App/requirements.txt .
RUN pip3 install -r requirements.txt
COPY . .
EXPOSE 50505
ENTRYPOINT ["gunicorn", "App:app"]
