import random
import sympy


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def is_prime(n):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def generate_keypair(p = 61 , q = 53):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    elif p == q:
        raise ValueError("p and q cannot be equal.")

    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = sympy.mod_inverse(e, phi)

    return ((e, n), (d, n))


def encrypt(pk, plaintext):
    e, n = pk
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher


def decrypt(pk, ciphertext):
    d, n = pk
    plain = [chr(pow(char, d, n)) for char in ciphertext]
    return ''.join(plain)


# Generate a key pair

public_key, private_key = generate_keypair(p=61, q=53)

# Encrypt a message
# message = "Hello, World!"
# cipher = encrypt(public_key, message)
# print("Encrypted message:", cipher)
#
# # Decrypt the message
# plain = decrypt(private_key, cipher)
# # print("Decrypted message:", plain)
# print("public key", type(private_key))
# print("cipher", type(cipher))
#
#
# print("private key", private_key)
