"""
GraVal encryptor/challenge generator.
"""

import time
import argparse
import uvicorn
import asyncio
import base64
import hashlib
from ipaddress import ip_address
from loguru import logger
from graval import Validator
from bittensor_wallet.keypair import Keypair
from fastapi import FastAPI, Request, status, HTTPException, Response


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
        version="0.2.5",
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

    @app.post("/encrypt")
    async def encrypt_payload(request: Request):
        """
        Encrypt an input payload for the specified device.
        """
        data = await request.json()
        await _filter(request)
        device_info = data["device_info"]
        payload = data["payload"]
        seed = data.get("seed")
        if not isinstance(payload, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="payload must be str type"
            )
        async with gpu_lock:
            kwargs = {"iterations": data.get("iterations", 1)}
            if isinstance(seed, int) and seed > 0:
                kwargs["override_seed"] = seed
            ciphertext, iv, length, seed = await asyncio.to_thread(
                validator.encrypt, device_info, payload, **kwargs
            )
            logger.success(
                f"Generated {length} byte ciphertext for {device_info['uuid']} and {seed=}"
            )
            return Response(
                content=f"{seed}|" + base64.b64encode(iv + ciphertext).decode(),
                media_type="text/plain",
            )

    @app.post("/check_proof")
    async def check_proof(request: Request):
        """
        Check if a proof is valid.
        """
        proof = await request.json()
        async with gpu_lock:
            return {
                "result": validator.check_proof(
                    proof["device_info"],
                    proof["seed"],
                    0,
                    proof["work_product"],
                    index=proof.get("check_index", 0),
                )
            }

    @app.post("/verify_device_challenge")
    async def verify_device_info_challenge(request: Request):
        """
        Compare a device info challenge/response to expected value.
        """
        data = await request.json()
        await _filter(request)
        devices = data["devices"]
        challenge = data["challenge"]
        response = data["response"]
        result = await asyncio.to_thread(
            validator.verify_device_info_challenge, challenge, response, devices
        )
        return {"result": result}

    @app.get("/ping")
    async def ping():
        return "pong"

    uvicorn.run(app=app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
