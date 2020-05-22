from pwn import remote, log
from json import loads, dumps
from protocol import server_port, proof_times
from random import randint


if __name__ == '__main__':
    s = remote("localhost", server_port)
    print(s.recvline().decode())
    params = loads(s.recvline())
    g = params["g"]
    p = params["p"]
    h = params["h"]
    print(params)

    res = []
    for cnt in range(proof_times):
        log.info(f"~~~~~ round {cnt + 1} ~~~~~")
        x = loads(s.recvline())["x"]
        log.info(f"  I got x: {x}")
        c = randint(0, 1)
        log.info(f"  I send c: {c}")
        s.sendline(dumps({"c": c}))
        y = loads(s.recvline())["y"]
        log.info(f"  I got y: {y}")
        if pow(g, y, p) == x * pow(h, c, p) % p:
            log.info("  Accepted")
            res.append(True)
        else:
            log.warn("  wrong responce...")
            res.append(False)
    s.close()

    if all(res):
        log.info("Alice is a valid prover")
    else:
        log.warn("Alice is not a valid prover")
