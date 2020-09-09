import random
import math
import base64


def get_param_by_key(params, key, message):
    if (key in params) and (len(params) > (params.index(key) + 1)):
        ind = params.index(key)
        param = params[ind + 1]
    else:
        print(message)
        param = input()
    return param


# using Euclid's algorithm
def inverse(a, module):
    a = a % module
    if math.gcd(a, module) != 1:
        return 0
    n = 1
    s, t = module, a
    q, r = s // t, s % t
    p_prev, p = 0, 1
    while r != 0:
        p_prev, p = p, p * q + p_prev
        s, t = t, r
        q, r = s // t, s % t
        n += 1
    if n % 2 == 0:
        p *= -1
    return p


def print_commands():
    print("-------------------------------------------------------------------")
    print("List of commands: \t\t| /help")
    print("Generate the keys:\t\t| /gen [-n n] [-b b]")
    print("Encrypt the password: \t| /enc [-k pathToKey] [-p password]")
    print("Decrypt the password: \t| /dec [-k pathToKey] [-c ciphertext]")
    print("Exit program: \t\t\t| /exit")
    print("-------------------------------------------------------------------")


def key_generation_mode(params):
    n = int(get_param_by_key(params, "-n", "Enter n"))
    b = int(get_param_by_key(params, "-b", "Enter b"))
    u = [0] * n
    module = 0
    assert b > n
    while module == 0:
        u_sum = 0
        for i in range(0, n):
            u[i] = random.randint(u_sum + 1, 2**(b - n + i) - 1)
            u_sum += u[i]
            if u_sum >= 2 ** (b - n + i + 1) - 1:
                break
        if u_sum < 2 ** b - 1:
            module = random.randint(u_sum + 1, 2**b - 1)
    a = module
    while math.gcd(a, module) != 1:
        a = random.randint(2, module - 1)
    w = [0] * n
    for i in range(n):
        w[i] = (inverse(a, module) * u[i]) % module
    print("secret key: u =", u, ", a =", a, ", N =", module)
    print("public key: w =", w)
    with open("public_key.txt", "w") as f:
        for i in range(n):
            f.writelines(str(w[i]) + "\n")
    pass


def encryption_mode(params):
    word = get_param_by_key(params, "-w", "Enter word to be encrypted")
    key_path = get_param_by_key(params, "-k", "Enter path to file with previously registered public key:")
    w = []
    with open("public_key.txt", "r") as f:
        s = f.readline()
        while s:
            w.append(int(s))
            s = f.readline()
    m_bytes = word.encode("utf-8")
    m = [0] * (8 * len(m_bytes))
    assert len(w) == len(m)
    for i in range(len(m_bytes)):
        b = m_bytes[i]
        for j in range(8):
            m[8*i + (7-j)] = b & 1
            b = b >> 1
    c = 0
    for i in range(len(w)):
        c += m[i] * w[i]
    print("Ct =", base64.b32encode(str(c).encode("utf-8")).decode("utf-8"))
    pass


def dot_product(v1, v2):
    assert len(v1) == len(v2)
    s = 0
    for i in range(len(v1)):
        s += (v1[i] * v2[i])
    return s


def orto(b):
    n = len(b)
    c = [[0] * n for i in range(n)]
    for i in range(n):
        for j in range(n):
            c[i][j] = b[i][j]
    for i in range(n):
        for j in range(i):
            for k in range(n):
                c[i][k] -= mu(b[i], c[j]) * c[j][k]
    return c


def mu(v1, v2):
    try:
        d = dot_product(v1, v2) / dot_product(v2, v2)
    except ZeroDivisionError:
        print("Zero division  error:", v1, v2)
        exit(1)
    return d


def lll_algorithm(a):
    n = len(a)
    b = [[0] * n for i in range(n)]
    for i in range(n):
        for j in range(n):
            b[i][j] = a[i][j]
    delta = 1 / 3
    orto_b = orto(b)
    i = 1
    while i < n:
        exchange = False
        tmp = [0] * n
        for j in range(i-1, -1, -1): #1, i-1
            orto_b = orto(b)
            e = int(mu(b[i], orto_b[j]))
            if mu(b[i], orto_b[j]) - int(mu(b[i], orto_b[j])) >= 0.5:
                e = int(mu(b[i], orto_b[j])) + 1
            if e:
                for k in range(n):
                    b[i][k] = b[i][k] - e*b[j][k]
            orto_b = orto(b)
            mu_0 = mu(b[i], orto_b[i-1])
        for j in range(n):
            tmp[j] = orto_b[i-1][j] * mu_0 + orto_b[i][j]
        if delta * dot_product(orto_b[i-1], orto_b[i-1]) > dot_product(tmp, tmp):
            b[i], b[i-1] = b[i-1], b[i]
            orto_b = orto(b)
            i = max(i-1, 0)
        else:
            i += 1
    return b


def solve_mh(basis):
    n = len(basis) - 1
    ans = lll_algorithm(basis)
    found = -1
    for i in range(n + 1):
        if ans[i][n] != 0:
            continue
        found = i
        for j in range(n):
            if ans[i][j] not in (0, 1):
                found = -1
            break
        if found != -1:
            return ans[found]
    return []


def decode_word(ans):
    m = 0
    for i in range(len(ans)):
        m *= 2
        m += ans[i]
    word = m.to_bytes(len(ans) // 8, "big").decode("utf-8")
    print("Hacked! Word was", word)


def decryption_mode(params):
    ct = get_param_by_key(params, "-c", "Enter ciphertext in base32 to be encrypted")
    w = []
    with open("public_key.txt", "r") as f:
        s = f.readline()
        while s:
            w.append(int(s))
            s = f.readline()
    key_path = get_param_by_key(params, "-k", "Enter path to file with previously registered public key:")
    s = int(base64.b32decode(ct.encode("utf-8")).decode("utf-8"))
    n = len(w)
    basis = [[0] * (n + 1) for i in range(n + 1)]
    for i in range(n):
        basis[i][i] = 1
        basis[i][n] = - w[i]
    basis[n][n] = s
    d = n/math.log(max([math.sqrt(dot_product(basis[i], basis[i])) for i in range(n+1)]), 2)
    print("d=", d)
    if d>=0.646:
        print("Attack won't be successful")
    ans = solve_mh(basis)
    if ans:
        decode_word(ans)
    basis[n][n] *= (-1)
    for i in range(n):
        basis[n][n] += w[i]
    ans = solve_mh(basis)
    if ans:
        decode_word(ans)
    pass


def main():
    print("Welcome to Merkle-Hellman Crack! Here are the commands available:")
    print_commands()
    while 1:
        command = input()
        if not command:
            continue
        if command == "/exit":
            print("Exiting...")
            break
        params = command.split(" ")
        option = params[0]
        if option == "/gen":
            key_generation_mode(params)
        elif option == "/enc":
            encryption_mode(params)
        elif option == "/dec":
            decryption_mode(params)
        elif option == "/help":
            print_commands()
        else:
            print("Some unknown command. Try this:")
            print_commands()


if __name__ == "__main__":
    main()
