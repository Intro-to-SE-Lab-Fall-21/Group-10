FROM ubuntu:latest
RUN apt-get update && apt-get install -y gnupg2
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10
RUN apt-get update
RUN mkdir -p /data/db
EXPOSE 5000
CMD ["--port 5000"]
ENTRYPOINT /usr/bin
