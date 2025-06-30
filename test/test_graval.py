import time
import os
import uuid
import hashlib
import pytest
from graval.validator import Validator
from graval.miner import Miner
from graval.structures import GraValError


def test_encrypt_decrypt():
    """
    Test encrypting messages as miner and decrypting as validator (and vice versa).
    Also test proof verification.
    """
    miner = Miner()
    validator = Validator()

    # Get miner device info.
    device_info = miner.get_device_info(0)

    # Test with multiple iterations to ensure proof checking works
    iterations = 1

    # Encrypt as the validator.
    plaintext = "Testing a super secret message..."
    ciphertext, iv, length, seed = validator.encrypt(
        device_info, plaintext, iterations, override_seed=42
    )
    print(f"Encrypted (validator): '{plaintext}' -- {length} bytes ciphertext")
    print(f"{ciphertext.hex()} {iv.hex()} {length=} {seed=}")

    # Decrypt as miner (this also generates the work product).
    work_products = miner.prove(seed, iterations)
    decrypted = miner.decrypt(seed, ciphertext, iv, length, 0)
    print(f"Decrypted (miner):     '{decrypted}'")
    assert decrypted == plaintext, f"'{decrypted}' vs '{plaintext}'"

    # Verify the miner's proof
    print(f"\nVerifying proof with {iterations} iterations...")

    # Get the work product for device 0
    work_product = None
    for wp in work_products:
        if wp["device_id"] == 0:
            work_product = wp["work_product"]
            break

    assert work_product is not None, "No work product found for device 0"

    # Check proof at each iteration
    all_checks_passed = True
    for check_iter in range(iterations):
        # Use index=0 to let the validator choose the optimal spot check index
        passed = validator.check_proof(device_info, seed, check_iter, work_product, index=0)
        print(f"Proof check for iteration {check_iter}: {'PASSED' if passed else 'FAILED'}")
        if not passed:
            all_checks_passed = False

    assert all_checks_passed, "Proof verification failed"
    print("All proof checks PASSED!")

    # Also test with an explicit index (e.g., matrix 10)
    if work_product["num_matrices"] > 10:
        print("\nTesting with explicit check index 10...")
        passed = validator.check_proof(device_info, seed, 0, work_product, index=10)
        print(f"Proof check with explicit index 10: {'PASSED' if passed else 'FAILED'}")
        assert passed, "Proof verification with explicit index failed"

    miner.shutdown()
    validator.shutdown()


def test_device_info_challenge():
    miner = Miner()
    device_count = miner._device_count
    devices = [miner.get_device_info(idx) for idx in range(device_count)]
    validator = Validator()
    for _ in range(200):
        started_at = time.time()
        challenge = validator.generate_device_info_challenge(device_count)
        delta = time.time() - started_at
        started_at = time.time()
        response = miner.process_device_info_challenge(challenge)
        delta2 = time.time() - started_at
        started_at = time.time()
        assert validator.verify_device_info_challenge(challenge, response, devices)
        delta3 = time.time() - started_at
        print(f"Device challenge: gen={delta} proc={delta2} ver={delta3}")
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
