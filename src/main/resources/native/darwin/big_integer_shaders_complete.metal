/**
 * Big Integer Operations for Metal GPU
 * Implements 3072-bit big integer operations using Montgomery multiplication
 */

#include <metal_stdlib>
using namespace metal;

// Big integer size (3072 bits = 96 * 32 bits)
constant uint BIGINT_SIZE = 96;
constant uint BIGINT_BITS = 3072;

// Big integer structure
struct BigInteger {
    uint32_t data[96];
};

// ============================================================================
// Helper Functions for Big Integer Operations
// ============================================================================

// Compare two big integers: returns -1 if a < b, 0 if a == b, 1 if a > b
int bigint_compare(device const BigInteger& a, device const BigInteger& b) {
    for (int i = BIGINT_SIZE - 1; i >= 0; i--) {
        if (a.data[i] > b.data[i]) return 1;
        if (a.data[i] < b.data[i]) return -1;
    }
    return 0;
}

// Check if big integer is zero
bool bigint_is_zero(device const BigInteger& a) {
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        if (a.data[i] != 0) return false;
    }
    return true;
}

// Copy big integer
void bigint_copy(device BigInteger& dst, device const BigInteger& src) {
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        dst.data[i] = src.data[i];
    }
}

// Set big integer to zero
void bigint_set_zero(device BigInteger& a) {
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        a.data[i] = 0;
    }
}

// Add two big integers with carry
uint bigint_add(device BigInteger& result, device const BigInteger& a, device const BigInteger& b) {
    uint64_t carry = 0;
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        uint64_t sum = (uint64_t)a.data[i] + (uint64_t)b.data[i] + carry;
        result.data[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return (uint)carry;
}

// Subtract two big integers with borrow
uint bigint_sub(device BigInteger& result, device const BigInteger& a, device const BigInteger& b) {
    uint64_t borrow = 0;
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        uint64_t diff = (uint64_t)a.data[i] - (uint64_t)b.data[i] - borrow;
        result.data[i] = (uint32_t)diff;
        borrow = (diff >> 32) & 1;
    }
    return (uint)borrow;
}

// Multiply big integer by a 32-bit word and add to result
void bigint_muladd(device BigInteger& result, device const BigInteger& a, uint32_t b, uint offset) {
    uint64_t carry = 0;
    for (uint i = 0; i < BIGINT_SIZE && (i + offset) < BIGINT_SIZE; i++) {
        uint64_t prod = (uint64_t)a.data[i] * (uint64_t)b + result.data[i + offset] + carry;
        result.data[i + offset] = (uint32_t)prod;
        carry = prod >> 32;
    }
}

// Multiply two big integers (simple schoolbook multiplication)
void bigint_mul(device BigInteger& result, device const BigInteger& a, device const BigInteger& b) {
    BigInteger temp;
    bigint_set_zero(temp);

    for (uint i = 0; i < BIGINT_SIZE; i++) {
        if (b.data[i] != 0) {
            bigint_muladd(temp, a, b.data[i], i);
        }
    }

    bigint_copy(result, temp);
}

// ============================================================================
// Montgomery Multiplication
// ============================================================================

// Calculate R mod n (R = 2^3072)
void bigint_calc_r_mod_n(device BigInteger& result, device const BigInteger& n) {
    // R = 2^3072, R mod n = R - n (if R > n)
    // This is a simplification; actual implementation needs proper calculation
    BigInteger temp;
    bigint_set_zero(temp);
    temp.data[0] = 1; // Start with 1

    // Multiply by 2 for 3072 times (this is R)
    // In practice, we'd use a more efficient method
    for (uint i = 0; i < BIGINT_BITS; i++) {
        // Shift left by 1
        uint32_t carry = 0;
        for (uint j = 0; j < BIGINT_SIZE; j++) {
            uint32_t new_carry = temp.data[j] >> 31;
            temp.data[j] = (temp.data[j] << 1) | carry;
            carry = new_carry;
        }

        // If temp >= n, subtract n
        if (bigint_compare(temp, n) >= 0) {
            bigint_sub(temp, temp, n);
        }
    }

    bigint_copy(result, temp);
}

// Calculate R^2 mod n (R = 2^3072, so R^2 = 2^6144)
void bigint_calc_r2_mod_n(device BigInteger& result, device const BigInteger& n) {
    BigInteger temp;
    bigint_set_zero(temp);
    temp.data[0] = 1; // Start with 1

    // Multiply by 2 for 6144 times (this is R^2)
    for (uint i = 0; i < BIGINT_BITS * 2; i++) {
        uint32_t carry = 0;
        for (uint j = 0; j < BIGINT_SIZE; j++) {
            uint32_t new_carry = temp.data[j] >> 31;
            temp.data[j] = (temp.data[j] << 1) | carry;
            carry = new_carry;
        }

        if (bigint_compare(temp, n) >= 0) {
            bigint_sub(temp, temp, n);
        }
    }

    bigint_copy(result, temp);
}

// Compute n' = -n^{-1} mod 2^32 for Montgomery multiplication
uint32_t montgomery_compute_n_prime(device const BigInteger& n) {
    uint32_t n0 = n.data[0];
    uint32_t inv = 1;
    // Newton-Raphson iteration to compute modular inverse mod 2^32
    for (uint i = 0; i < 5; i++) {
        inv = inv * (2u - n0 * inv);
    }
    return (uint32_t)(0u - inv);
}

// Montgomery reduction
void montgomery_reduce(device BigInteger& result, device BigInteger& t, device const BigInteger& n, uint32_t n_prime) {
    BigInteger temp;
    bigint_copy(temp, t);

    for (uint i = 0; i < BIGINT_SIZE; i++) {
        uint32_t m = temp.data[i] * n_prime;

        // temp = temp + m * n * (2^32)^i
        uint64_t carry = 0;
        for (uint j = 0; j < BIGINT_SIZE && (i + j) < BIGINT_SIZE; j++) {
            uint64_t prod = (uint64_t)n.data[j] * (uint64_t)m + temp.data[i + j] + carry;
            temp.data[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
    }

    // Shift right by 3072 bits (96 words)
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        if (i < BIGINT_SIZE) {
            result.data[i] = temp.data[i];
        }
    }

    // If result >= n, subtract n
    if (bigint_compare(result, n) >= 0) {
        bigint_sub(result, result, n);
    }
}

// Montgomery multiplication: result = a * b * R^-1 mod n
void montgomery_mul(device BigInteger& result, device const BigInteger& a, device const BigInteger& b,
                    device const BigInteger& n, uint32_t n_prime) {
    BigInteger t;
    bigint_set_zero(t);

    // t = a * b
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        if (b.data[i] != 0) {
            uint64_t carry = 0;
            for (uint j = 0; j < BIGINT_SIZE && (i + j) < BIGINT_SIZE * 2; j++) {
                uint64_t prod = (uint64_t)a.data[j] * (uint64_t)b.data[i] + t.data[i + j] + carry;
                t.data[i + j] = (uint32_t)prod;
                carry = prod >> 32;
            }
        }

        // Montgomery reduction step
        uint32_t m = t.data[i] * n_prime;
        uint64_t carry2 = 0;
        for (uint j = 0; j < BIGINT_SIZE && (i + j) < BIGINT_SIZE * 2; j++) {
            uint64_t prod = (uint64_t)n.data[j] * (uint64_t)m + t.data[i + j] + carry2;
            t.data[i + j] = (uint32_t)prod;
            carry2 = prod >> 32;
        }
    }

    // Final reduction
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        result.data[i] = t.data[i + BIGINT_SIZE];
    }

    // If result >= n, subtract n
    if (bigint_compare(result, n) >= 0) {
        bigint_sub(result, result, n);
    }
}

// Modular multiplication using Montgomery form: result = (a * b) mod n
void montgomery_mul_mod(device BigInteger& result, device const BigInteger& a, device const BigInteger& b,
                        device const BigInteger& n, device const BigInteger& r2, uint32_t n_prime) {
    BigInteger a_mont;
    BigInteger b_mont;
    BigInteger t;

    montgomery_mul(a_mont, a, r2, n, n_prime);
    montgomery_mul(b_mont, b, r2, n, n_prime);
    montgomery_mul(t, a_mont, b_mont, n, n_prime);

    BigInteger one;
    bigint_set_zero(one);
    one.data[0] = 1;
    montgomery_mul(result, t, one, n, n_prime);
}

// Modular exponentiation using Montgomery multiplication
void mod_exp_montgomery(device BigInteger& result, device const BigInteger& base,
                        device const BigInteger& exp, device const BigInteger& n,
                        device const BigInteger& r, device const BigInteger& r2, uint32_t n_prime) {
    // Convert base to Montgomery form: base' = base * R mod n
    BigInteger base_mont;
    montgomery_mul(base_mont, base, r2, n, n_prime);

    // Initialize result to 1 in Montgomery form: result' = R mod n
    bigint_copy(result, r);

    // Square and multiply
    for (int i = BIGINT_SIZE - 1; i >= 0; i--) {
        for (int j = 31; j >= 0; j--) {
            // Square
            BigInteger temp;
            montgomery_mul(temp, result, result, n, n_prime);
            bigint_copy(result, temp);

            // Multiply if bit is set
            if ((exp.data[i] >> j) & 1) {
                montgomery_mul(temp, result, base_mont, n, n_prime);
                bigint_copy(result, temp);
            }
        }
    }

    // Convert back from Montgomery form: result = result' * R^-1 mod n
    BigInteger one;
    bigint_set_zero(one);
    one.data[0] = 1;
    montgomery_mul(result, result, one, n, n_prime);
}

// ============================================================================
// Kernel Functions
// ============================================================================

// Modular exponentiation kernel
kernel void modPowKernel(
    device const BigInteger* bases [[buffer(0)]],
    device const BigInteger* exps [[buffer(1)]],
    device const BigInteger* mods [[buffer(2)]],
    device BigInteger* results [[buffer(3)]],
    constant uint& numLength [[buffer(4)]],
    constant uint& count [[buffer(5)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= count) return;

    BigInteger r;
    BigInteger r2;
    uint32_t n_prime = montgomery_compute_n_prime(mods[id]);
    bigint_calc_r_mod_n(r, mods[id]);
    bigint_calc_r2_mod_n(r2, mods[id]);

    mod_exp_montgomery(results[id], bases[id], exps[id], mods[id], r, r2, n_prime);
}

// Batch modular exponentiation kernel
kernel void batchModPowKernel(
    device const BigInteger* bases [[buffer(0)]],
    device const BigInteger* exp [[buffer(1)]],
    device const BigInteger* mod [[buffer(2)]],
    device BigInteger* results [[buffer(3)]],
    constant uint& numLength [[buffer(4)]],
    constant uint& count [[buffer(5)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= count) return;

    BigInteger r;
    BigInteger r2;
    uint32_t n_prime = montgomery_compute_n_prime(mod[0]);
    bigint_calc_r_mod_n(r, mod[0]);
    bigint_calc_r2_mod_n(r2, mod[0]);

    mod_exp_montgomery(results[id], bases[id], exp[0], mod[0], r, r2, n_prime);
}

// Compute AffG Proof Tuple kernel
kernel void computeAffGProofTupleKernel(
    device const BigInteger* C [[buffer(0)]],
    device const BigInteger* N0 [[buffer(1)]],
    device const BigInteger* N0sq [[buffer(2)]],
    device const BigInteger* N1 [[buffer(3)]],
    device const BigInteger* N1sq [[buffer(4)]],
    device const BigInteger* alphas [[buffer(5)]],
    device const BigInteger* betasForN0 [[buffer(6)]],
    device const BigInteger* betasForN1 [[buffer(7)]],
    device const BigInteger* rs [[buffer(8)]],
    device const BigInteger* ss [[buffer(9)]],
    device BigInteger* Aj_results [[buffer(10)]],
    device BigInteger* Bj_results [[buffer(11)]],
    constant uint& numLength [[buffer(12)]],
    constant uint& kappa [[buffer(13)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= kappa) return;

    BigInteger rN0;
    BigInteger r2N0;
    BigInteger rN1;
    BigInteger r2N1;
    uint32_t n0_prime = montgomery_compute_n_prime(N0sq[0]);
    uint32_t n1_prime = montgomery_compute_n_prime(N1sq[0]);
    bigint_calc_r_mod_n(rN0, N0sq[0]);
    bigint_calc_r2_mod_n(r2N0, N0sq[0]);
    bigint_calc_r_mod_n(rN1, N1sq[0]);
    bigint_calc_r2_mod_n(r2N1, N1sq[0]);

    BigInteger onePlusN0;
    BigInteger onePlusN1;
    BigInteger one;
    bigint_set_zero(one);
    one.data[0] = 1;
    bigint_add(onePlusN0, N0[0], one);
    bigint_add(onePlusN1, N1[0], one);

    BigInteger c_pow_alpha;
    BigInteger onePlusN0_pow_beta;
    BigInteger r_pow_n0;
    mod_exp_montgomery(c_pow_alpha, C[0], alphas[id], N0sq[0], rN0, r2N0, n0_prime);
    mod_exp_montgomery(onePlusN0_pow_beta, onePlusN0, betasForN0[id], N0sq[0], rN0, r2N0, n0_prime);
    mod_exp_montgomery(r_pow_n0, rs[id], N0[0], N0sq[0], rN0, r2N0, n0_prime);

    BigInteger tmp;
    montgomery_mul_mod(tmp, c_pow_alpha, onePlusN0_pow_beta, N0sq[0], r2N0, n0_prime);
    montgomery_mul_mod(Aj_results[id], tmp, r_pow_n0, N0sq[0], r2N0, n0_prime);

    BigInteger onePlusN1_pow_beta;
    BigInteger s_pow_n1;
    mod_exp_montgomery(onePlusN1_pow_beta, onePlusN1, betasForN1[id], N1sq[0], rN1, r2N1, n1_prime);
    mod_exp_montgomery(s_pow_n1, ss[id], N1[0], N1sq[0], rN1, r2N1, n1_prime);

    montgomery_mul_mod(Bj_results[id], onePlusN1_pow_beta, s_pow_n1, N1sq[0], r2N1, n1_prime);
}

// Compute Dec Proof Tuple kernel
kernel void computeDecProofTupleKernel(
    device const BigInteger* K [[buffer(0)]],
    device const BigInteger* N0 [[buffer(1)]],
    device const BigInteger* N0sq [[buffer(2)]],
    device const BigInteger* negAlphas [[buffer(3)]],
    device const BigInteger* betas [[buffer(4)]],
    device const BigInteger* rs [[buffer(5)]],
    device BigInteger* A_results [[buffer(6)]],
    constant uint& numLength [[buffer(7)]],
    constant uint& kappa [[buffer(8)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= kappa) return;

    BigInteger rN0;
    BigInteger r2N0;
    uint32_t n0_prime = montgomery_compute_n_prime(N0sq[0]);
    bigint_calc_r_mod_n(rN0, N0sq[0]);
    bigint_calc_r2_mod_n(r2N0, N0sq[0]);

    BigInteger onePlusN0;
    BigInteger one;
    bigint_set_zero(one);
    one.data[0] = 1;
    bigint_add(onePlusN0, N0[0], one);

    BigInteger k_pow_alpha;
    BigInteger onePlusN0_pow_beta;
    BigInteger r_pow_n0;
    // negAlphas should be precomputed on host as -alpha (non-negative magnitude)
    mod_exp_montgomery(k_pow_alpha, K[0], negAlphas[id], N0sq[0], rN0, r2N0, n0_prime);
    mod_exp_montgomery(onePlusN0_pow_beta, onePlusN0, betas[id], N0sq[0], rN0, r2N0, n0_prime);
    mod_exp_montgomery(r_pow_n0, rs[id], N0[0], N0sq[0], rN0, r2N0, n0_prime);

    BigInteger tmp;
    montgomery_mul_mod(tmp, k_pow_alpha, onePlusN0_pow_beta, N0sq[0], r2N0, n0_prime);
    montgomery_mul_mod(A_results[id], tmp, r_pow_n0, N0sq[0], r2N0, n0_prime);
}
