"""
micro-ecc secp256k1 implementation re-written to Python.
Most function might work with other curves as well,
but this has not been tested.

Copyright (c) 2014, Kenneth MacKay
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
NUM_BITS = 256


def regularize_k(k: int) -> tuple[int, int, int]:
    """
    Regularize scalar k by adding curve order n.
    Returns (k0, k1, carry) where:
    - k0 = k + n
    - k1 = k0 + n = k + 2n
    - carry indicates if k0 >= 2^NUM_BITS
    """
    k0 = k + N
    carry = 1 if k0 >= (1 << NUM_BITS) else 0
    k0 = k0 % (1 << NUM_BITS)
    k1 = (k0 + N) % (1 << NUM_BITS)
    return k0, k1, carry


def test_bit(vli: int, bit: int) -> int:
    return (vli >> bit) & 1


def mod_sub(left: int, right: int, mod: int) -> int:
    return (left - right) % mod


def mod_mult(left: int, right: int, mod: int) -> int:
    return (left * right) % mod


def mod_inv(x: int, mod: int) -> int:
    return pow(x, -1, mod)


def apply_z(x1: list[int], y1: list[int], z: list[int]) -> None:
    t1 = (z[0] * z[0]) % P      # z^2
    x1[0] = (x1[0] * t1) % P    # x1 * z^2
    t1 = (t1 * z[0]) % P        # z^3
    y1[0] = (y1[0] * t1) % P    # y1 * z^3


def double_jacobian(x1: list[int], y1: list[int], z1: list[int]) -> None:
    # t1 = X, t2 = Y, t3 = Z
    if z1[0] == 0:
        return

    t5 = (y1[0] * y1[0]) % P  # t5 = y1^2
    t4 = (x1[0] * t5) % P     # t4 = x1*y1^2 = A
    x1[0] = (x1[0] * x1[0]) % P  # t1 = x1^2
    t5 = (t5 * t5) % P        # t5 = y1^4
    z1[0] = (y1[0] * z1[0]) % P  # t3 = y1*z1 = z3

    y1[0] = (x1[0] + x1[0]) % P  # t2 = 2*x1^2
    y1[0] = (y1[0] + x1[0]) % P  # t2 = 3*x1^2
    if y1[0] & 1:
        y1[0] = (y1[0] + P) >> 1
    else:
        y1[0] = y1[0] >> 1
    # t2 = 3/2*(x1^2) = B

    x1[0] = (y1[0] * y1[0]) % P  # t1 = B^2
    x1[0] = (x1[0] - t4) % P     # t1 = B^2 - A
    x1[0] = (x1[0] - t4) % P     # t1 = B^2 - 2A = x3

    t4 = (t4 - x1[0]) % P        # t4 = A - x3
    y1[0] = (y1[0] * t4) % P     # t2 = B * (A - x3)
    y1[0] = (y1[0] - t5) % P     # t2 = B * (A - x3) - y1^4 = y3


def xycz_initial_double(
    x1: list[int], y1: list[int], x2: list[int], y2: list[int], initial_z: list[int]
) -> None:
    z = [initial_z[0]]

    x2[0] = x1[0]
    y2[0] = y1[0]

    apply_z(x1, y1, z)
    double_jacobian(x1, y1, z)
    apply_z(x2, y2, z)


# Input P = (x1, y1, Z), Q = (x2, y2, Z)
# Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
# or P => P', Q => P + Q
# sub = x1' - x3 (used for subsequent call to XYcZ_addC()).
def xycz_add(x1: list[int], y1: list[int], x2: list[int], y2: list[int], sub: list[int]) -> None:
    # t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
    t5 = (x2[0] - x1[0]) % P   # t5 = x2 - x1
    t5 = (t5 * t5) % P         # t5 = (x2 - x1)^2 = A
    x1[0] = (x1[0] * t5) % P   # x1' = x1*A = B
    x2[0] = (x2[0] * t5) % P   # t3 = x2*A = C
    y2[0] = (y2[0] - y1[0]) % P  # t4 = y2 - y1
    t5 = (y2[0] * y2[0]) % P   # t5 = (y2 - y1)^2 = D

    t5 = (t5 - x1[0]) % P      # t5 = D - B
    t5 = (t5 - x2[0]) % P      # t5 = D - B - C = x3
    x2[0] = (x2[0] - x1[0]) % P  # t3 = C - B
    y1[0] = (y1[0] * x2[0]) % P  # y1' = y1*(C - B)
    sub[0] = (x1[0] - t5) % P  # s = B - x3
    y2[0] = (y2[0] * sub[0]) % P  # t4 = (y2 - y1)*(B - x3)
    y2[0] = (y2[0] - y1[0]) % P  # t4 = y3

    x2[0] = t5  # move x3 to output


# Input P = (x1, y1, Z), Q = (x2, y2, Z), sub = x1 - x2
# Output P - Q = (x3', y3', Z3), P + Q = (x3, y3, Z3)
# or P => P - Q, Q => P + Q
def xycz_addc(x1: list[int], y1: list[int], x2: list[int], y2: list[int], sub: list[int]) -> None:
    # t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
    t5 = (sub[0] * sub[0]) % P  # t5 = (x2 - x1)^2 = A
    x1[0] = (x1[0] * t5) % P    # t1 = x1*A = B
    x2[0] = (x2[0] * t5) % P    # t3 = x2*A = C
    t5 = (y2[0] + y1[0]) % P    # t5 = y2 + y1
    y2[0] = (y2[0] - y1[0]) % P  # t4 = y2 - y1

    t6 = (x2[0] - x1[0]) % P    # t6 = C - B
    y1[0] = (y1[0] * t6) % P    # t2 = y1 * (C - B) = E
    t6 = (x1[0] + x2[0]) % P    # t6 = B + C
    x2[0] = (y2[0] * y2[0]) % P  # t3 = (y2 - y1)^2 = D
    x2[0] = (x2[0] - t6) % P    # t3 = D - (B + C) = x3

    t7 = (x1[0] - x2[0]) % P    # t7 = B - x3
    y2[0] = (y2[0] * t7) % P    # t4 = (y2 - y1)*(B - x3)
    y2[0] = (y2[0] - y1[0]) % P  # t4 = (y2 - y1)*(B - x3) - E = y3

    t7 = (t5 * t5) % P          # t7 = (y2 + y1)^2 = F
    t7 = (t7 - t6) % P          # t7 = F - (B + C) = x3'
    t6 = (t7 - x1[0]) % P       # t6 = x3' - B
    t6 = (t6 * t5) % P          # t6 = (y2+y1)*(x3' - B)
    y1[0] = (t6 - y1[0]) % P    # t2 = (y2+y1)*(x3' - B) - E = y3'

    x1[0] = t7  # move x3' to output


def ecc_point_mult(
    point: tuple[int, int],
    scalar: int,
    initial_z: int,
) -> tuple[int, int]:
    rx: list[list[int]] = [[0], [0]]
    ry: list[list[int]] = [[0], [0]]

    rx[1][0] = point[0]
    ry[1][0] = point[1]

    xycz_initial_double(rx[1], ry[1], rx[0], ry[0], [initial_z])
    sub = [mod_sub(rx[0][0], rx[1][0], P)]

    for i in range(NUM_BITS - 1, 0, -1):
        nb = int(not test_bit(scalar, i))
        xycz_addc(rx[1 - nb], ry[1 - nb], rx[nb], ry[nb], sub)
        xycz_add(rx[nb], ry[nb], rx[1 - nb], ry[1 - nb], sub)
    return finish_ecc_point_mult(point, scalar, rx, ry, sub)


def finish_ecc_point_mult(
    point: tuple[int, int],
    scalar: int,
    rx_input: list[list[int]],
    ry_input: list[list[int]],
    sub_input: list[int],
) -> tuple[int, int]:
    # Lets avoid list-passing problems.
    rx = [rx_input[0].copy(), rx_input[1].copy()]
    ry = [ry_input[0].copy(), ry_input[1].copy()]
    sub = sub_input.copy()
    nb = int(not test_bit(scalar, 0))
    xycz_addc(rx[1 - nb], ry[1 - nb], rx[nb], ry[nb], sub)

    # Find final 1/Z value.
    z = mod_sub(rx[1][0], rx[0][0], P)  # X1 - X0
    z = mod_mult(z, ry[1 - nb][0], P)   # Yb * (X1 - X0)
    z = mod_mult(z, point[0], P)        # xP * Yb * (X1 - X0)
    z = mod_inv(z, P)                   # 1 / (xP * Yb * (X1 - X0))
    z = mod_mult(z, point[1], P)        # yP / (xP * Yb * (X1 - X0))
    z = mod_mult(z, rx[1 - nb][0], P)   # Xb * yP / (xP * Yb * (X1 - X0))
    # End 1/Z calculation

    xycz_add(rx[nb], ry[nb], rx[1 - nb], ry[1 - nb], sub)
    apply_z(rx[0], ry[0], [z])

    return rx[0][0], ry[0][0]
