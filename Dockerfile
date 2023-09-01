FROM python:3.11
WORKDIR /App
COPY requirements.txt .
RUN pip3 install -r requirements.txt
EXPOSE 5000
CMD ["--port 5000"]
