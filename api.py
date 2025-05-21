"""
GraVal encryptor/challenge generator.
"""

import time
import argparse
import uvicorn
import asyncio
import base64
import hashlib
import json
from typing import Optional
from ipaddress import ip_address
from loguru import logger
from pydantic import BaseModel
from graval import Validator
from bittensor_wallet.keypair import Keypair
from fastapi import FastAPI, Request, status, HTTPException, Response


class Cipher(BaseModel):
    ciphertext: str
    iv: str
    length: int
    iterations: Optional[int] = 1


class Challenge(Cipher):
    seed: int
    plaintext: str


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
    )
    parser.add_argument(
        "--validator-whitelist",
        type=str,
    )
    parser.add_argument(
        "--block-external",
        action="store_true",
    )
    args = parser.parse_args()

    validator = Validator()
    if hasattr(validator, "initialize"):
        validator.initialize()

    app = FastAPI(
        title="GraVal as an API",
        description="GPU validation service.",
        version="0.1.1",
    )
    gpu_lock = asyncio.Lock()

    def verify_request(request: Request, whitelist: list[str], extra_key: str = "graval") -> None:
        """
        Verify the authenticity of a request.
        """
        validator_hotkey = request.headers.get("X-Validator")
        nonce = request.headers.get("X-Nonce")
        signature = request.headers.get("X-Signature")
        if (
            any(not v for v in [validator_hotkey, nonce, signature])
            or validator_hotkey not in whitelist
            or int(time.time()) - int(nonce) >= 30
        ):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="go away")
        signature_string = ":".join(
            [
                validator_hotkey,
                nonce,
                extra_key,
            ]
        )
        if not Keypair(ss58_address=validator_hotkey).verify(
            signature_string, bytes.fromhex(signature)
        ):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="go away")

    def _block_external(request: Request):
        """
        Limit traffic to internal IPs.
        """
        x_forwarded_for = request.headers.get("X-Forwarded-For")
        actual_ip = x_forwarded_for.split(",")[0] if x_forwarded_for else request.client.host
        ip = ip_address(actual_ip)
        is_private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        if not is_private:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="go away")

    async def _filter(request: Request):
        """
        Filter requests by internal/external traffic and/or whitelisted keys.
        """
        if args.block_external:
            _block_external(request)
        if args.validator_whitelist:
            request_body = await request.body()
            sha2 = hashlib.sha256(request_body).hexdigest()
            verify_request(request, args.validator_whitelist.split(","), extra_key=sha2)

    @app.post("/decrypt")
    async def decrypt_payload(request: Request) -> str:
        """
        Decrypt an encrypted payload.
        """
        data = await request.json()
        await _filter(request)
        device_info = data["device_info"]
        payload = data["payload"]
        seed = data["seed"]
        iterations = data.get("iterations", 1)
        iv, ciphertext = None, None
        try:
            bytes_ = base64.b64decode(payload)
            iv = bytes_[:16]
            ciphertext = bytes_[16:]
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid payload")

        args = [None, validator.decrypt, device_info, ciphertext, iv, len(ciphertext), seed]
        if not hasattr(validator, "initialize"):
            args.append(iterations)

        async with gpu_lock:
            loop = asyncio.get_event_loop()
            decrypted = await loop.run_in_executor(*args)
            logger.success(f"Decrypted payload: {len(decrypted)} bytes from {device_info['uuid']}")
            return Response(content=base64.b64encode(decrypted.encode()).decode(), media_type="text/plain")

    @app.post("/encrypt")
    async def encrypt_payload(request: Request):
        """
        Encrypt an input payload for the specified device.
        """
        data = await request.json()
        await _filter(request)
        device_info = data["device_info"]
        payload = data["payload"]
        if not isinstance(payload, str):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="payload must be str type")
        seed = data["seed"]
        iterations = data.get("iterations", 1)
        encrypted_payload = {}
        async with gpu_lock:
            loop = asyncio.get_event_loop()
            args = [None, validator.encrypt, device_info, payload, seed]
            if not hasattr(validator, "initialize"):
                args.append(iterations)
            ciphertext, iv, length = await loop.run_in_executor(*args)
            logger.success(f"Generated {length} byte ciphertext for {device_info['uuid']}")
            return Response(content=base64.b64encode(iv + ciphertext).decode(), media_type="text/plain")

    @app.get("/ping")
    async def ping():
        return "pong"

    uvicorn.run(app=app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
