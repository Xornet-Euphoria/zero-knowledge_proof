from pwn import listen, log
from Crypto.Util.number import getPrime, isPrime
from Crypto.Random.random import randint
from json import loads, dumps
from protocol import server_port, proof_times


def get_safe_prime(n):
    while True:
        p = getPrime(n)
        q = p - 1
        s = 0
        # print(p)
        while q % 2 == 0:
            s += 1
            q //= 2

        if isPrime(q):
            assert p == (pow(2, s) * q + 1)
            return (p, q, s)


def is_primitive_root(g, p):
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    for i in range(s):
        if pow(g, pow(2, i), p) == 1:
            return False

    if pow(g, q, p) == 1:
        return False

    return True


def geng():
    p, q, s = get_safe_prime(256)

    for i in range(2, p):
        if is_primitive_root(i, p):
            g = i
            break

    return {"p": p, "g": g}


def make_secret(g, p):
    x_floor = exponent_floor(g, p)

    x = randint(x_floor, p)

    return (x, pow(g, x, p))


def exponent_floor(g, p):
    """
        return minimum x for pow(g, x) > p
    """
    x_floor = 1
    while True:
        if pow(g, x_floor) > p:
            break
        x_floor += 1

    return x_floor


if __name__ == '__main__':
    params = geng()
    g = params["g"]
    p = params["p"]
    res = make_secret(g, p)
    secret = res[0]
    h = res[1]
    params["h"] = h
    assert pow(g, secret, p) == h

    log.info("parameters are set.")
    print(params)
    log.info(f"secret -> {secret}")

    l = listen(server_port)
    l.sendline(b"Hi bob. This is our parameters.")
    l.sendline(dumps(params))

    r_floor = exponent_floor(g, p)
    for cnt in range(proof_times):
        r = randint(r_floor, p)
        x = pow(g, r, p)
        l.sendline(dumps({"x": x}))

        c = loads(l.recvline())["c"]
        log.info(f"I got c: {c}")
        l.sendline(dumps({"y": r + secret * c}))
    l.close()
