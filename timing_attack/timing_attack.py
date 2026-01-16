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

def recover_secret_via_timing(check_func, length: int):
    recovered = bytearray()
    timing_log = []

    for pos in range(length):
        best_byte = None
        best_time = -1.0
        times_for_all = {}

        for candidate in range(256):
            probe = bytes(recovered + bytes([candidate]) + bytes([0])*(length - pos - 1))
            samples = []
            for _ in range(TRIALS_PER_CANDIDATE):
                dt = time_call(check_func, probe)
                samples.append(dt)
            avg = statistics.mean(samples)
            times_for_all[candidate] = avg
            if avg > best_time:
                best_time = avg
                best_byte = candidate

        recovered.append(best_byte)
        timing_log.append((pos, best_byte, best_time, times_for_all))
        print(f"position {pos}: {best_byte:02x} avg_time={best_time:.8f}s")

    return bytes(recovered), timing_log

if __name__ == "__main__":
    secret = secrets.token_bytes(SECRET_LEN)
    print(f"Secret: {secret.hex()}\n")

    print("Running insecure...")
    def server_insecure_check(probe):
        return insecure_compare(secret, probe)

    start = time.time()
    recovered, _ = recover_secret_via_timing(server_insecure_check, SECRET_LEN)
    elapsed = time.time() - start
    print(f"\nRecovered insecure: {recovered.hex()}")
    print(f"Time elapsed: {elapsed:.2f}s\n")

    print("Running compare_digest...")
    def server_secure_check(probe):
        return secure_compare(secret, probe)

    start = time.time()
    recovered2, _ = recover_secret_via_timing(server_secure_check, SECRET_LEN)
    elapsed2 = time.time() - start
    print(f"\nRecovered compare_digest: {recovered2.hex()}")
    print(f"Time elapsed: {elapsed2:.2f}s\n")

    print("Secret (hex):", secret.hex())
    print("Recovered insecure:", recovered.hex())
    print("Recovered compare_digest:", recovered2.hex())

