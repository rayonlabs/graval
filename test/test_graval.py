import os
import uuid
import random
import hashlib
import pytest
from graval.validator import Validator
from graval.miner import Miner
from graval.structures import GraValError


def test_encrypt_decrypt():
    """
    Test encrypting messages as miner and decrypting as validator (and vice versa).
    """
    miner = Miner()
    validator = Validator()

    # Validator generates a unique seed.
    seed = random.randint(0, 100000)

    # Initialize the miner node.
    miner.initialize(seed)
    device_info = miner.get_device_info(0)
    print(f"Miner device info: {device_info}")

    # Encrypt as the validator.
    plaintext = "Testing a super secret message..."
    ciphertext, iv, length = validator.encrypt(device_info, plaintext, seed)
    print(f"Encrypted (validator): '{plaintext}' -- {length} bytes ciphertext")
    print(f"{ciphertext.hex()} {iv.hex()} {length=}")

    ## Decrypt as the miner.
    decrypted = miner.decrypt(ciphertext, iv, length, 0)
    print(f"Decrypted (miner):     '{decrypted}'")
    assert decrypted == plaintext, f"'{decrypted}' vs '{plaintext}'"

    # Encrypt as the miner.
    plaintext += " As a miner..."
    ciphertext, iv, length = miner.encrypt(plaintext)
    print(f"Encrypted (miner):     '{plaintext}' -- {length} bytes")
    decrypted = validator.decrypt(device_info, ciphertext, iv, length, seed)
    print(f"Decrypted (validator): '{decrypted}'")
    assert plaintext == decrypted
    print("Successfully verified encryption/decryption")

    miner.shutdown()
    validator.shutdown()


def test_matrix_challenge():
    miner = Miner()
    validator = Validator()

    # Initialize, but really only so we can get the device info.
    _ = miner.initialize(42, 1)
    device_info = miner.get_device_info(0)

    # Generate a random string, which we'll encrypt with a random seed.
    challenge_string = str(uuid.uuid4())
    seed = random.randint(0, 10000000)
    ciphertext, iv, length = validator.generate_matrix_challenge(
        seed, device_info, challenge_string
    )

    # Simulate the miner responding to the matrix challenge.
    miner_response = miner.process_matrix_challenge(seed, ciphertext, iv, length)
    assert miner_response == challenge_string
    print(f"Successfully responded to challenge string: {miner_response}")
    miner.shutdown()
    validator.shutdown()


def test_device_info_challenge():
    miner = Miner()
    device_count = miner._device_count
    devices = [miner.get_device_info(idx) for idx in range(device_count)]
    validator = Validator()
    for _ in range(200):
        challenge = validator.generate_device_info_challenge(device_count)
        response = miner.process_device_info_challenge(challenge)
        assert validator.verify_device_info_challenge(challenge, response, devices)
    print("Successfully verified 200 device info challenges")
    miner.shutdown()
    validator.shutdown()


def test_filesystem_challenge():
    miner = Miner()
    path = os.path.abspath(__file__)
    size = os.path.getsize(path)
    chunk_size = 64
    with open(path, "rb") as infile:
        file_bytes = infile.read()
    for i in range(int(size / chunk_size)):
        expected = hashlib.sha256(
            file_bytes[i * chunk_size : i * chunk_size + chunk_size]
        ).hexdigest()
        miner_output = miner.process_filesystem_challenge(path, i * chunk_size, chunk_size)
        assert expected == miner_output
    print(f"Successfully verified {int(size / chunk_size)} filesystem challenges.")

    # Check bad path.
    with pytest.raises(GraValError):
        miner.process_filesystem_challenge(str(uuid.uuid4()), 0, 24)

    # Check bad byte offset.
    with pytest.raises(GraValError):
        miner.process_filesystem_challenge(path, 0, 2 * 10**8)
    with pytest.raises(GraValError):
        miner.process_filesystem_challenge(path, 2 * 10**8, 4)
    with pytest.raises(GraValError):
        miner.process_filesystem_challenge(path, 0, 0)
    miner.shutdown()
