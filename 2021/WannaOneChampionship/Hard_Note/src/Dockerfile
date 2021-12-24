FROM ubuntu:21.10

RUN /usr/sbin/useradd -u 1000 user

RUN apt-get update && apt-get install -y socat

WORKDIR /home/user/

USER user

COPY flag.txt .

COPY hard_note .

EXPOSE 13337

CMD socat \
      TCP-LISTEN:13337,reuseaddr,fork \
      EXEC:"/home/user/hard_note"
