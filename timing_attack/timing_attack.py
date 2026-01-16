import time, secrets, statistics, hmac

SECRET_LEN = 6
PER_BYTE_DELAY = 0.001
TRIALS_PER_CANDIDATE = 8

def insecure_compare(secret: bytes, probe: bytes) -> bool:
    if len(probe) != len(secret):
        return False
    for a, b in zip(secret, probe):
        if a != b:
            return False
        time.sleep(PER_BYTE_DELAY)
    return True

def secure_compare(secret: bytes, probe: bytes) -> bool:
    return hmac.compare_digest(secret, probe)

def time_call(func, *args, **kwargs):
    t0 = time.perf_counter()
    func(*args, **kwargs)
    t1 = time.perf_counter()
    return t1 - t0