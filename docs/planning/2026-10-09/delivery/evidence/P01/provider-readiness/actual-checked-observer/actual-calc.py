"""calc - a tiny arithmetic library used by the report app."""


def add(a, b):
    return a + b


def mean(xs):
    xs = list(xs)
    if not xs:
        raise ValueError("mean of empty sequence")
    return sum(xs) / len(xs)


def median(xs):
    xs = sorted(xs)
    if not xs:
        raise ValueError("median of empty sequence")

    midpoint = len(xs) // 2
    if len(xs) % 2:
        return xs[midpoint]
    return (xs[midpoint - 1] + xs[midpoint]) / 2
