# GraVal
FROM parachutes/python:3.12.9
RUN pip install --upgrade graval==0.2.4 fastapi uvicorn loguru bittensor-wallet
ADD --chown=chutes api.py /app/api.py
ENTRYPOINT ["python", "api.py"]
