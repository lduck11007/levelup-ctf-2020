FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3-pip && pip3 install flask pycrypto

RUN useradd -ms /bin/bash user
COPY ./easy_oracle /easy_oracle
WORKDIR /easy_oracle

EXPOSE 80
USER user

CMD ["python3", "main.py"]