FROM python:3.7-alpine

COPY . /app
WORKDIR /app
RUN pip install /app

CMD [ "gunicorn", "-b", "0.0.0.0:8000", "url_shortener:app" ]
