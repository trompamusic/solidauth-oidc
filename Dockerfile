FROM python:3.11

RUN mkdir /code
WORKDIR /code

COPY requirements.txt /code

RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt

COPY . /code

CMD flask run