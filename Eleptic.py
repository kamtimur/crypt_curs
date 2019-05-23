class EllipticCurve:

    def __init__(self, p=0, a=0, b=0, P=(), q=0):

        """
		An elliptic curve over a prime field.
        The field is specified by the parameter 'p'.
        The curve coefficients are 'a' and 'b'.
        The base point of the cyclic subgroup is 'P'
        The order of the subgroup is 'q'.
        """

        self.p = p
        self.a = a
        self.b = b
        self.P = P
        self.q = q

        assert pow(2, p - 1, p) == 1
        assert (4 * a * a * a + 27 * b * b) % p != 0
        assert self.is_on_curve(P)
        assert self.mult(q, P) is None

    def is_on_curve(self, point):

        """Checks whether the given point lies on the elliptic curve."""
        if point is None:
            return True

        x, y = point
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def add(self, point1, point2):

        """Returns the result of point1 + point2 according to the group law."""
        assert self.is_on_curve(point1)
        assert self.is_on_curve(point2)

        if point1 is None:
            return point2

        if point2 is None:
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            m = (3 * x1 * x1 + self.a) * invert(2 * y1, self.p)
        else:
            m = (y1 - y2) * invert(x1 - x2, self.p)

        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        result = (x3 % self.p,
                  -y3 % self.p)

        assert self.is_on_curve(result)

        return result

    def double(self, point):

        """Returns 2 * point."""
        return self.add(point, point)

    def neg(self, point):

        """Returns -point."""
        if point is None:
            return None

        x, y = point
        result = x, -y % self.p

        assert self.is_on_curve(result)

        return result

    def mult(self, q, point):

        """Returns n * point computed using the double and add algorithm."""

        if q % self.q == 0 or point is None:
            return None

        if q < 0:
            return self.neg(self.mult(-q, point))

        result = None
        addend = point

        while q:

            if q & 1:
                result = self.add(result, addend)

            addend = self.double(addend)
            q >>= 1

        return result

    def __str__(self):

        a = abs(self.a)
        b = abs(self.b)
        a_sign = '-' if self.a < 0 else '+'
        b_sign = '-' if self.b < 0 else '+'

        return 'y^2 = (x^3 {} {}x {} {}) mod {}'.format(
            a_sign, a, b_sign, b, self.p)

def invert(q, p):

	"""Returns the inverse of n modulo p.

    This function returns the only integer x such that (x * n) % p == 1.

    n must be non-zero and p must be a prime.
    """

	if q == 0:

		raise ZeroDivisionError('division by zero')

	if q < 0:

		return p - invert(-q, p)

	s, old_s = 0, 1
	t, old_t = 1, 0
	r, old_r = p, q

	while r != 0:

		quotient = old_r // r
		old_r, r = r, old_r - quotient * r
		old_s, s = s, old_s - quotient * s
		old_t, t = t, old_s - quotient * t

	gcd, x, y = old_r, old_s, old_t

	assert gcd == 1
	assert (q * x) % p == 1

	return x % p
