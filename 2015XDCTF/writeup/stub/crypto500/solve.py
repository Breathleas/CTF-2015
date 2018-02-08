from pwn import *
import seccure
from gmpy import *

def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.

        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.

        0 is returned is no square root exists for
        these a and p.

        The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) / 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) / 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)

        Returns 1 if a has a square root modulo
        p, -1 otherwise.
    """
    ls = pow(a, (p - 1) / 2, p)
    return -1 if ls == p - 1 else ls

class dual_ec_dbrg(object):
    def __init__(self,seed,curve,qx,qy):
        self.i0 = seed
        self.curve = curve
        self.P = curve.base
        self.Q = seccure.AffinePoint(qx,qy,self.curve)
        if (not self.Q.on_curve):
            print "Chosen Q Not on Curve!"
            return

    def getrand(self):
        first = self.P * gmpy.mpz(self.i0)
        x = first.x
        out = self.Q * x
        self.i0 = int(first.x)
        return int(out.x)

URL = '133.130.52.128'
#URL = 'localhost'

r = remote(URL, 2345)
blob = r.recv().split()

x,y = blob[0].split(",")
x = int(x)
y = int(y)

d = blob[1]
d = int(d)

rand1 = blob[2]
rand1 = int(rand1)

#print x,y,rand1

p256 = seccure.Curve.by_name_substring("nistp256")
a = p256.a
b = p256.b
m = p256.m
a = int(a)
b = int(b)
m = int(m)

order = int(p256.order)
e = invert(mpz(d), order)
y_square = (pow(rand1, 3, m) + a * rand1 + b) % p256.m
new_y = modular_sqrt(y_square, p256.m)
curve = seccure.AffinePoint(rand1, new_y, p256)
orig = seccure.AffinePoint(x,y,p256)
assert(curve.on_curve)
i2 = curve * e
Q = orig * i2.x 
print Q.x
r.send("predict:" + str(Q.x))
print r.recv()
