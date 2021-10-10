FROM python:3.10.0-alpine3.14

COPY action.py /action.py

ENTRYPOINT ["python", "/action.py"]
