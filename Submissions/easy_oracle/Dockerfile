FROM python:3.8.4-alpine3.12
RUN apk add build-base
RUN pip3 install flask pycryptodome

COPY . /easy_oracle
WORKDIR /easy_oracle

EXPOSE 5000

CMD ["python", "main.py"]