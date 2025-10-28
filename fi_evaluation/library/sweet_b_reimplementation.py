"""
Sweet B secp256k1 implementation in Python.
Based on sb_sw_lib.c from Sweet B library.

Copyright (c) 2020 Western Digital Corporation or its affiliates.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from dataclasses import dataclass

# secp256k1 curve parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
NUM_BITS = 256

# dz_r values for secp256k1 (quasi-reduced form)
DZ_R_X = 1
DZ_R_Y = 1

# minus_a_r_over_three for secp256k1 (quasi-reduced form)
MINUS_A_R_OVER_THREE = P

# Montgomery arithmetic constants
R = 1 << 256  # R = 2^256
R2_MOD_P = 0x1000007A2000E90A1  # R^2 mod P (sb_sw_curves.h:191)
R_MOD_P = 0x1000003D1  # R mod P (sb_sw_curves.h:195)
P_MP = 0xD2253531  # -P^-1 mod 2^32 (sb_sw_curves.h:190, word size = 32 bits)

# P-2 factorization for modular inversion (sb_sw_curves.h:185-188)
P_MINUS_TWO_F1 = 0x037F6FF774E142D5C004A68677B5D811  # Hamming weight 64
P_MINUS_TWO_F2 = 0x4930562E37A2A6A01499B40D0074369E5D  # Hamming weight 58


def fe_lt(left: int, right: int) -> int:
    return 1 if left < right else 0


def fe_cond_sub_p(dest: int, c: int) -> int:
    # In C, this uses unsigned arithmetic which wraps at 2^256.
    # If dest < P, then dest - P wraps to dest - P + 2^256.
    subtracted = (dest - P) % (1 << 256)
    return subtracted if c else dest


def fe_qr(a: int, carry: int) -> int:
    b = fe_lt(P, a)
    a = fe_cond_sub_p(a, carry | b)
    # Convert 0 to P for quasi-reduced representation
    if a == 0:
        a = P
    assert a <= P, "quasi-reduction must always produce quasi-reduced output"
    assert a != 0, "quasi-reduction must always produce quasi-reduced output"
    return a


def mont_mult_reference(x: int, y: int) -> int:
    r_inv = pow(R_MOD_P, -1, P)
    result = (x * y * r_inv) % P
    if result == 0:
        result = P
    return result


def mont_mult(x: int, y: int) -> int:
    assert x <= P, "x must be quasi-reduced"
    assert y <= P, "y must be quasi-reduced"

    a = 0
    hw = 0

    for i in range(8):  # 8 words of 32 bits
        x_i = (x >> (32 * i)) & ((1 << 32) - 1)

        # A = A + x_i * y, track carry c
        a = a + x_i * y
        c = a >> 256  # Carry from first addition
        a = a & ((1 << 256) - 1)  # Keep only 256 bits

        # u_i = a_0 * m' mod b
        a_0 = a & ((1 << 32) - 1)
        u_i = (a_0 * P_MP) & ((1 << 32) - 1)

        # A = A + u_i * m, track carry c2
        a = a + u_i * P
        c2 = a >> 256  # Carry from second addition
        a = a & ((1 << 256) - 1)  # Keep only 256 bits

        # A = A / b (shift right by one word)
        a = a >> 32

        # Compute hw + c + c2, update hw and high word of a
        r = hw + c + c2
        hw = r >> 32  # New carry
        a = (a & ((1 << 224) - 1)) | ((r & ((1 << 32) - 1)) << 224)  # Set high word

    a = fe_qr(a, hw)

    return a


def mont_square(x: int) -> int:
    return mont_mult(x, x)


def mont_reduce(x: int) -> int:
    return mont_mult(x, 1)


def mod_expt_r(base: int, exponent: int) -> int:
    """Modular exponentiation in Montgomery domain (sb_fe_mod_expt_r)."""
    result = R_MOD_P
    by = False  # Track if we've seen the first 1 bit

    for i in range(NUM_BITS - 1, -1, -1):
        b = (exponent >> i) & 1
        if not by:
            if b:
                by = True
            else:
                continue
        result = mont_square(result)
        if b:
            result = mont_mult(result, base)

    return result


def mod_inv_r(x: int) -> int:
    """Modular inverse in Montgomery domain using factored P-2 (sb_fe_mod_inv_r)."""
    result = mod_expt_r(x, P_MINUS_TWO_F1)
    result = mod_expt_r(result, P_MINUS_TWO_F2)
    return result


def mont_convert(x: int) -> int:
    return mont_mult(x, R2_MOD_P)


def mod_add(x: int, y: int) -> int:
    result = (x + y) % P
    if result == 0:
        result = P
    return result


def mod_sub(x: int, y: int) -> int:
    result = (x - y) % P
    if result == 0:
        result = P
    return result


def mod_double(x: int) -> int:
    result = (2 * x) % P
    if result == 0:
        result = P
    return result


def mod_negate(x: int, modulus: int) -> int:
    return mod_sub_custom(modulus, x, modulus)


def mod_sub_custom(x: int, y: int, modulus: int) -> int:
    result = (x - y) % modulus
    if result == 0:
        result = modulus
    return result


def mod_halve(x: int) -> int:
    if test_bit(x, 0):
        x = x + N
    return x >> 1


def mod_reduce_full(x: int) -> int:
    return x % P


@dataclass
class State:
    i: int  # Bit index
    swap: int  # Swap flag for constant-time operations
    inv_k: bool  # True if scalar was negated
    k_one: bool  # True if scalar is 1


@dataclass
class Context:
    # Point 1 coordinates
    x1: int
    y1: int

    # Point 2 coordinates
    x2: int
    y2: int

    # Temporary variables
    t5: int
    t6: int
    t7: int
    t8: int

    # Multiplication parameters
    k: int  # Scalar
    z: int  # Z coordinate
    point_x: int  # Original point X
    point_y: int  # Original point Y

    # State
    state: State


def test_bit(value: int, bit: int) -> int:
    return (value >> bit) & 1


def fe_add(a: int, b: int) -> tuple[int, int]:
    result = a + b
    carry = 1 if result >= (1 << 256) else 0
    result = result % (1 << 256)
    return result, carry


def cswap(swap: int, a: int, b: int) -> tuple[int, int]:
    if swap:
        return b, a
    return a, b


def regularize_scalar(ctx: Context) -> None:
    ctx.t5, c_1 = fe_add(ctx.k, N)
    ctx.k, _ = fe_add(ctx.t5, N)
    ctx.k, ctx.t5 = cswap(c_1, ctx.k, ctx.t5)


def point_initial_double(ctx: Context) -> None:
    ctx.t5 = mod_double(ctx.y2)
    ctx.y1 = mont_square(ctx.x2)
    ctx.y1 = mod_sub(ctx.y1, MINUS_A_R_OVER_THREE)
    ctx.x1 = mod_double(ctx.y1)
    ctx.y1 = mod_add(ctx.y1, ctx.x1)

    ctx.t6 = mont_square(ctx.y2)
    ctx.y2 = mod_double(ctx.t6)
    ctx.t6 = mod_double(ctx.y2)
    ctx.x1 = mont_mult(ctx.x2, ctx.t6)

    ctx.x2 = mont_square(ctx.y1)
    ctx.x2 = mod_sub(ctx.x2, ctx.x1)
    ctx.x2 = mod_sub(ctx.x2, ctx.x1)

    ctx.t6 = mod_sub(ctx.x1, ctx.x2)
    ctx.t7 = mont_mult(ctx.y1, ctx.t6)

    ctx.y1 = mont_square(ctx.y2)
    ctx.y1 = mod_double(ctx.y1)
    ctx.y2 = mod_sub(ctx.t7, ctx.y1)


def point_co_z_add_update(ctx: Context) -> None:
    # Merged with the inlined sb_sw_point_co_z_add_update
    ctx.t6 = mod_sub(ctx.x2, ctx.x1)  # t6 = x2 - x1 = Z'/Z
    ctx.t5 = mont_square(ctx.t6)  # t5 = (x2-x1)^2 = A
    ctx.t6 = mont_mult(ctx.x2, ctx.t5)  # t6 = x2 * A = C
    ctx.x2 = mont_mult(ctx.x1, ctx.t5)  # x2 = x1 * A = B (becomes x1')
    ctx.t7 = mod_sub(ctx.y2, ctx.y1)  # t7 = y2 - y1
    ctx.t5 = mod_add(ctx.x2, ctx.t6)  # t5 = B + C
    ctx.t6 = mod_sub(ctx.t6, ctx.x2)  # t6 = C - B
    ctx.y2 = mont_mult(ctx.y1, ctx.t6)  # y2 = y1 * (Z'/Z)^3 = E
    ctx.x1 = mont_square(ctx.t7)  # x1 = (y2-y1)^2 = D
    ctx.x1 = mod_sub(ctx.x1, ctx.t5)  # x1 = D - B - C
    ctx.t6 = mod_sub(ctx.x2, ctx.x1)  # t6 = B - x3
    ctx.y1 = mont_mult(ctx.t7, ctx.t6)  # y1 = (y2-y1) * (B-x3)
    ctx.y1 = mod_sub(ctx.y1, ctx.y2)  # y1 = y3


def point_co_z_conj_add(ctx: Context) -> None:
    ctx.t8 = mod_add(ctx.y1, ctx.y2)  # t8 = y1 + y2

    point_co_z_add_update(ctx)

    ctx.t6 = ctx.x2
    ctx.t7 = ctx.y2

    ctx.x2 = mont_square(ctx.t8)  # x2 = (y1+y2)^2 = F
    ctx.x2 = mod_sub(ctx.x2, ctx.t5)  # x2 = F - (B+C)

    ctx.t5 = mod_sub(ctx.x2, ctx.t6)  # t5 = x3' - B
    ctx.y2 = mont_mult(ctx.t8, ctx.t5)  # y2 = (y1+y2) * (x3'-B)
    ctx.y2 = mod_sub(ctx.y2, ctx.t7)  # y2 = y3'


def point_mult_start(ctx: Context) -> None:
    ctx.state = State(i=255, swap=0, inv_k=False, k_one=False)

    is_zero = 1 if ctx.point_x == P else 0

    ctx.y1 = mont_reduce(ctx.point_y)
    zero_sign = test_bit(ctx.y1, 0)

    ctx.x1 = DZ_R_X
    ctx.y1 = DZ_R_Y

    ctx.y2 = mod_negate(ctx.y1, P)

    ctx.y1, ctx.y2 = cswap(zero_sign, ctx.y1, ctx.y2)

    ctx.t5 = mod_halve(ctx.k)

    ctx.k, ctx.t5 = cswap(is_zero, ctx.k, ctx.t5)
    ctx.point_x, ctx.x1 = cswap(is_zero, ctx.point_x, ctx.x1)
    ctx.point_y, ctx.y1 = cswap(is_zero, ctx.point_y, ctx.y1)

    ctx.state.inv_k = bool(test_bit(ctx.k, 255))
    ctx.t5 = mod_negate(ctx.k, N)
    ctx.k, ctx.t5 = cswap(ctx.state.inv_k, ctx.k, ctx.t5)

    ctx.state.k_one = ctx.k == 1

    regularize_scalar(ctx)

    ctx.x2 = ctx.point_x
    ctx.y2 = ctx.point_y

    point_initial_double(ctx)

    ctx.t7 = mont_square(ctx.z)
    ctx.t6 = mont_mult(ctx.z, ctx.t7)

    ctx.t5 = ctx.x1
    ctx.x1 = mont_mult(ctx.t5, ctx.t7)

    ctx.t5 = ctx.y1
    ctx.y1 = mont_mult(ctx.t5, ctx.t6)

    ctx.t5 = ctx.x2
    ctx.x2 = mont_mult(ctx.t5, ctx.t7)

    ctx.t5 = ctx.y2
    ctx.y2 = mont_mult(ctx.t5, ctx.t6)

    ctx.state.i = 255


def point_mult_iteration(ctx: Context):
    k_bit = test_bit(ctx.k, ctx.state.i)

    ctx.state.swap ^= k_bit
    ctx.x1, ctx.x2 = cswap(ctx.state.swap, ctx.x1, ctx.x2)
    ctx.y1, ctx.y2 = cswap(ctx.state.swap, ctx.y1, ctx.y2)
    ctx.state.swap = k_bit

    point_co_z_conj_add(ctx)

    point_co_z_add_update(ctx)

    ctx.state.i -= 1


def point_mult_final_iteration(ctx: Context):
    k_bit = test_bit(ctx.k, 0)

    ctx.state.swap ^= k_bit
    ctx.x1, ctx.x2 = cswap(ctx.state.swap, ctx.x1, ctx.x2)
    ctx.y1, ctx.y2 = cswap(ctx.state.swap, ctx.y1, ctx.y2)

    point_co_z_conj_add(ctx)

    ctx.x1, ctx.x2 = cswap(k_bit, ctx.x1, ctx.x2)
    ctx.y1, ctx.y2 = cswap(k_bit, ctx.y1, ctx.y2)

    ctx.t8 = mod_sub(ctx.x1, ctx.x2)

    ctx.x1, ctx.x2 = cswap(k_bit, ctx.x1, ctx.x2)
    ctx.y1, ctx.y2 = cswap(k_bit, ctx.y1, ctx.y2)

    ctx.t5 = mont_mult(ctx.t8, ctx.y2)
    ctx.t8 = mont_mult(ctx.t5, ctx.point_x)

    ctx.t8 = mod_inv_r(ctx.t8)

    ctx.t5 = mont_mult(ctx.t8, ctx.point_y)
    ctx.t8 = mont_mult(ctx.t5, ctx.x2)

    point_co_z_add_update(ctx)

    ctx.x1, ctx.x2 = cswap(k_bit ^ 1, ctx.x1, ctx.x2)
    ctx.y1, ctx.y2 = cswap(k_bit ^ 1, ctx.y1, ctx.y2)

    ctx.t5 = mont_square(ctx.t8)
    ctx.t6 = mont_mult(ctx.t5, ctx.t8)

    ctx.t7 = mont_mult(ctx.t5, ctx.x2)

    ctx.x2 = mod_add(ctx.t7, ctx.point_x)
    ctx.t7, ctx.x2 = cswap(ctx.state.k_one, ctx.t7, ctx.x2)

    ctx.x1 = mont_reduce(ctx.t7)

    ctx.t7 = mont_mult(ctx.t6, ctx.y2)

    ctx.y2 = mod_add(ctx.t7, ctx.point_y)
    ctx.t7, ctx.y2 = cswap(ctx.state.k_one, ctx.t7, ctx.y2)

    ctx.y1 = mont_reduce(ctx.t7)

    ctx.t5 = mod_negate(ctx.y1, P)
    ctx.y1, ctx.t5 = cswap(ctx.state.inv_k, ctx.y1, ctx.t5)

    # Consciously ignoring the final scalar restoration.


def point_mult_continue(ctx: Context) -> None:
    while ctx.state.i > 0:
        # Consciously ignoring the 16-bit chunking.
        point_mult_iteration(ctx)
    if ctx.state.i == 0:
        point_mult_final_iteration(ctx)


def shared_secret_start(ctx: Context, private_key: int, public_key_x: int, public_key_y: int, initial_z: int) -> None:
    ctx.z = initial_z
    ctx.k = private_key

    ctx.point_x = public_key_x
    ctx.point_y = public_key_y

    ctx.x1 = ctx.point_x
    ctx.y1 = ctx.point_y

    ctx.point_x = mont_convert(ctx.x1)
    ctx.point_y = mont_convert(ctx.y1)

    point_mult_start(ctx)


def shared_secret_continue(ctx: Context) -> None:
    point_mult_continue(ctx)


def shared_secret_finish(ctx: Context) -> int:
    ctx.x1 = mod_reduce_full(ctx.x1)
    return ctx.x1


def shared_secret(private_key: int, public_key_x: int, public_key_y: int, initial_z: int = R_MOD_P) -> int:
    ctx = Context(
        x1=0, y1=0, x2=0, y2=0,
        t5=0, t6=0, t7=0, t8=0,
        k=0, z=0, point_x=0, point_y=0,
        state=State(i=0, swap=0, inv_k=False, k_one=False)
    )

    shared_secret_start(ctx, private_key, public_key_x, public_key_y, initial_z)

    shared_secret_continue(ctx)

    return shared_secret_finish(ctx)
