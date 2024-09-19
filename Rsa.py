import sympy as sp
import random as rand
# Methods
def totient(p,q):
    return (int(p)-1)*(int(q)-1)
def prime_finder():
    prime = rand.randint(100,500)
    while sp.isprime(prime) == False:
        prime = rand.randint(100,500)
    return prime
def gcd(p, q):
    # Use Euclid's algorithm to find the GCD.
    while q != 0:
        p, q = q, p % q
    return p
def public_e_finder(A):
    e = rand.randrange(1,A-1)
    while gcd(e,A) != 1:
        e = rand.randrange(1,A-1)
    return e
def private_d_finder(e,A):
    for d in range(3,A):
        if (d * e ) % A == 1:
            return d
    raise ValueError ("d is not found")
def encrypt(x,e,n):
    y = pow(x,e)
    return y % n
def decrypt(y,d,n):
    x = pow(y,d)
    return x % n


