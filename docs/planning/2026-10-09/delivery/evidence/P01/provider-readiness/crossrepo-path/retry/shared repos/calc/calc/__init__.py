"""calc - a tiny arithmetic library used by the report app."""


def add(a, b):
    return a + b


def mean(xs):
    xs = list(xs)
    if not xs:
        raise ValueError("mean of empty sequence")
    return sum(xs) / len(xs)
