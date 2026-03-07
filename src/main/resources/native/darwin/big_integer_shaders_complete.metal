/**
 * Big Integer Operations for Metal GPU
 * Implements 4096-bit big integer operations using Montgomery multiplication
 */

#include <metal_stdlib>
using namespace metal;

// Big integer size (4096 bits = 128 * 32 bits)
constant uint BIGINT_SIZE = 128;
constant uint BIGINT_BITS = 4096;
constant uint DOUBLE_BIGINT_SIZE = 256; // For multiplication results

// Big integer structure
struct BigInteger {
    uint32_t data[128];
};

// Double-sized big integer structure for multiplication
struct DoubleBigInteger {
    uint32_t data[256];
};

// ============================================================================
// Helper Functions for Big Integer Operations
// ============================================================================

// Compare two big integers: returns -1 if a < b, 0 if a == b, 1 if a > b
int bigint_compare(thread const BigInteger& a, thread const BigInteger& b) {
    for (int i = BIGINT_SIZE - 1; i >= 0; i--) {
        if (a.data[i] > b.data[i]) return 1;
        if (a.data[i] < b.data[i]) return -1;
    }
    return 0;
}

// Check if big integer is zero
bool bigint_is_zero(thread const BigInteger& a) {
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        if (a.data[i] != 0) return false;
    }
    return true;
}

// Copy big integer
void bigint_copy(thread BigInteger& dst, thread const BigInteger& src) {
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        dst.data[i] = src.data[i];
    }
}

// Set big integer to zero
void bigint_set_zero(thread BigInteger& a) {
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        a.data[i] = 0;
    }
}

// Add two big integers with carry
uint bigint_add(thread BigInteger& result, thread const BigInteger& a, thread const BigInteger& b) {
    uint64_t carry = 0;
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        uint64_t sum = (uint64_t)a.data[i] + (uint64_t)b.data[i] + carry;
        result.data[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return (uint)carry;
}

// Subtract two big integers with borrow
uint bigint_sub(thread BigInteger& result, thread const BigInteger& a, thread const BigInteger& b) {
    uint64_t borrow = 0;
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        uint64_t a_val = a.data[i];
        uint64_t b_val = b.data[i];
        uint64_t b_with_borrow = b_val + borrow;
        uint64_t diff = a_val - b_with_borrow;
        result.data[i] = (uint32_t)diff;
        borrow = (a_val < b_with_borrow) ? 1 : 0;
    }
    return (uint)borrow;
}

// Multiply big integer by a 32-bit word and add to result
void bigint_muladd(thread BigInteger& result, thread const BigInteger& a, uint32_t b, uint offset) {
    uint64_t carry = 0;
    for (uint i = 0; i < BIGINT_SIZE && (i + offset) < BIGINT_SIZE; i++) {
        uint64_t prod = (uint64_t)a.data[i] * (uint64_t)b + result.data[i + offset] + carry;
        result.data[i + offset] = (uint32_t)prod;
        carry = prod >> 32;
    }
}

// Multiply two big integers (simple schoolbook multiplication)
void bigint_mul(thread BigInteger& result, thread const BigInteger& a, thread const BigInteger& b) {
    thread DoubleBigInteger temp;
    for (uint i = 0; i < DOUBLE_BIGINT_SIZE; i++) {
        temp.data[i] = 0;
    }

    for (uint i = 0; i < BIGINT_SIZE; i++) {
        if (b.data[i] != 0) {
            uint64_t carry = 0;
            for (uint j = 0; j < BIGINT_SIZE; j++) {
                if (i + j < DOUBLE_BIGINT_SIZE) {
                    uint64_t prod = (uint64_t)a.data[j] * (uint64_t)b.data[i] + temp.data[i + j] + carry;
                    temp.data[i + j] = (uint32_t)prod;
                    carry = prod >> 32;
                }
            }
            // Handle remaining carry
            uint k = BIGINT_SIZE;
            while (carry > 0 && i + k < DOUBLE_BIGINT_SIZE) {
                uint64_t sum = temp.data[i + k] + carry;
                temp.data[i + k] = (uint32_t)sum;
                carry = sum >> 32;
                k++;
            }
        }
    }

    // Copy lower BIGINT_SIZE words to result
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        result.data[i] = temp.data[i];
    }
}

// ============================================================================
// Montgomery Multiplication
// ============================================================================

// Double a mod n without overflow: result = (a * 2) mod n, assuming 0 <= a < n
void bigint_double_mod(thread BigInteger& result, thread const BigInteger& a, thread const BigInteger& n) {
    // If a >= n - a, then a + a >= n and result = a + a - n
    thread BigInteger n_minus_a;
    bigint_sub(n_minus_a, n, a);
    if (bigint_compare(a, n_minus_a) >= 0) {
        thread BigInteger tmp;
        bigint_sub(tmp, a, n_minus_a); // a - (n - a) = 2a - n
        bigint_copy(result, tmp);
    } else {
        thread BigInteger tmp;
        bigint_add(tmp, a, a);
        bigint_copy(result, tmp);
    }
}

// Calculate R mod n (R = 2^4096)
void bigint_calc_r_mod_n(thread BigInteger& result, thread const BigInteger& n) {
    thread BigInteger r;
    bigint_set_zero(r);
    r.data[0] = 1;
    for (uint i = 0; i < BIGINT_BITS; i++) {
        thread BigInteger tmp;
        bigint_double_mod(tmp, r, n);
        bigint_copy(r, tmp);
    }
    bigint_copy(result, r);
}

// Calculate R^2 mod n (R = 2^4096, so R^2 = 2^8192)
void bigint_calc_r2_mod_n(thread BigInteger& result, thread const BigInteger& n) {
    thread BigInteger r;
    bigint_calc_r_mod_n(r, n);
    thread BigInteger r2;
    bigint_copy(r2, r);
    for (uint i = 0; i < BIGINT_BITS; i++) {
        thread BigInteger tmp;
        bigint_double_mod(tmp, r2, n);
        bigint_copy(r2, tmp);
    }
    bigint_copy(result, r2);
}

// Compute n' = -n^{-1} mod 2^32 for Montgomery multiplication
uint32_t montgomery_compute_n_prime(thread const BigInteger& n) {
    uint32_t n0 = n.data[0];
    uint32_t inv = 1;
    // Newton-Raphson iteration to compute modular inverse mod 2^32
    for (uint i = 0; i < 5; i++) {
        inv = inv * (2u - n0 * inv);
    }
    return (uint32_t)(0u - inv);
}

// Montgomery reduction
void montgomery_reduce(thread BigInteger& result, thread DoubleBigInteger& t, thread const BigInteger& n, uint32_t n_prime) {
    thread DoubleBigInteger temp;
    for (uint i = 0; i < DOUBLE_BIGINT_SIZE; i++) {
        temp.data[i] = t.data[i];
    }

    for (uint i = 0; i < BIGINT_SIZE; i++) {
        uint32_t m = temp.data[i] * n_prime;

        // temp = temp + m * n * (2^32)^i
        uint64_t carry = 0;
        for (uint j = 0; j < BIGINT_SIZE; j++) {
            if (i + j < DOUBLE_BIGINT_SIZE) {
                uint64_t prod = (uint64_t)n.data[j] * (uint64_t)m + temp.data[i + j] + carry;
                temp.data[i + j] = (uint32_t)prod;
                carry = prod >> 32;
            }
        }
        // Handle remaining carry
        uint k = BIGINT_SIZE;
        while (carry > 0 && i + k < DOUBLE_BIGINT_SIZE) {
            uint64_t sum = temp.data[i + k] + carry;
            temp.data[i + k] = (uint32_t)sum;
            carry = sum >> 32;
            k++;
        }
    }

    // Shift right by BIGINT_BITS - copy upper BIGINT_SIZE words
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        result.data[i] = temp.data[i + BIGINT_SIZE];
    }

    // If result >= n, subtract n
    if (bigint_compare(result, n) >= 0) {
        bigint_sub(result, result, n);
    }
}

// Montgomery multiplication: result = a * b * R^-1 mod n
void montgomery_mul(thread BigInteger& result, thread const BigInteger& a, thread const BigInteger& b,
                    thread const BigInteger& n, uint32_t n_prime) {
    thread DoubleBigInteger t;
    for (uint i = 0; i < DOUBLE_BIGINT_SIZE; i++) {
        t.data[i] = 0;
    }

    // t = a * b
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        if (b.data[i] != 0) {
            uint64_t carry = 0;
            for (uint j = 0; j < BIGINT_SIZE; j++) {
                if (i + j < DOUBLE_BIGINT_SIZE) {
                    uint64_t prod = (uint64_t)a.data[j] * (uint64_t)b.data[i] + t.data[i + j] + carry;
                    t.data[i + j] = (uint32_t)prod;
                    carry = prod >> 32;
                }
            }
            // Handle remaining carry
            uint k = BIGINT_SIZE;
            while (carry > 0 && i + k < DOUBLE_BIGINT_SIZE) {
                uint64_t sum = t.data[i + k] + carry;
                t.data[i + k] = (uint32_t)sum;
                carry = sum >> 32;
                k++;
            }
        }
    }

    // Perform Montgomery reduction
    thread DoubleBigInteger temp;
    for (uint i = 0; i < DOUBLE_BIGINT_SIZE; i++) {
        temp.data[i] = t.data[i];
    }

    for (uint i = 0; i < BIGINT_SIZE; i++) {
        uint32_t m = temp.data[i] * n_prime;

        // temp = temp + m * n * (2^32)^i
        uint64_t carry = 0;
        for (uint j = 0; j < BIGINT_SIZE; j++) {
            if (i + j < DOUBLE_BIGINT_SIZE) {
                uint64_t prod = (uint64_t)n.data[j] * (uint64_t)m + temp.data[i + j] + carry;
                temp.data[i + j] = (uint32_t)prod;
                carry = prod >> 32;
            }
        }
        // Handle remaining carry
        uint k = BIGINT_SIZE;
        while (carry > 0 && i + k < DOUBLE_BIGINT_SIZE) {
            uint64_t sum = temp.data[i + k] + carry;
            temp.data[i + k] = (uint32_t)sum;
            carry = sum >> 32;
            k++;
        }
    }

    // Shift right by BIGINT_BITS - copy upper BIGINT_SIZE words
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        result.data[i] = temp.data[i + BIGINT_SIZE];
    }

    // If result >= n, subtract n
    if (bigint_compare(result, n) >= 0) {
        bigint_sub(result, result, n);
    }
}

// Modular multiplication using Montgomery form: result = (a * b) mod n
void montgomery_mul_mod(thread BigInteger& result, thread const BigInteger& a, thread const BigInteger& b,
                        thread const BigInteger& n, thread const BigInteger& r2, uint32_t n_prime) {
    thread BigInteger a_mont;
    thread BigInteger b_mont;
    thread BigInteger t;

    montgomery_mul(a_mont, a, r2, n, n_prime);
    montgomery_mul(b_mont, b, r2, n, n_prime);
    montgomery_mul(t, a_mont, b_mont, n, n_prime);

    thread BigInteger one;
    bigint_set_zero(one);
    one.data[0] = 1;
    montgomery_mul(result, t, one, n, n_prime);
}

bool bigint_is_negative(thread const BigInteger& a) {
    return (a.data[BIGINT_SIZE - 1] & 0x80000000u) != 0;
}

void bigint_abs_twos_complement(thread BigInteger& result, thread const BigInteger& a) {
    uint64_t carry = 1;
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        uint32_t v = ~a.data[i];
        uint64_t sum = (uint64_t)v + carry;
        result.data[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
}

// Modular exponentiation using Montgomery multiplication (unsigned exponent)
void mod_exp_montgomery_unsigned(thread BigInteger& result, thread const BigInteger& base,
                                 thread const BigInteger& exp, thread const BigInteger& n,
                                 thread const BigInteger& r, thread const BigInteger& r2, uint32_t n_prime) {
    // Convert base to Montgomery form: base' = base * R mod n
    thread BigInteger base_mont;
    montgomery_mul(base_mont, base, r2, n, n_prime);

    // Initialize result to 1 in Montgomery form: result' = R mod n
    bigint_copy(result, r);

    // Left-to-right square-and-multiply
    for (int i = BIGINT_SIZE - 1; i >= 0; i--) {
        for (int j = 31; j >= 0; j--) {
            thread BigInteger temp;
            // Square
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
    thread BigInteger one;
    bigint_set_zero(one);
    one.data[0] = 1;
    montgomery_mul(result, result, one, n, n_prime);
}

// Modular exponentiation with signed exponent (use precomputed base inverse for negative)
void mod_exp_montgomery_signed(thread BigInteger& result,
                               thread const BigInteger& base,
                               thread const BigInteger& base_inv,
                               thread const BigInteger& exp,
                               thread const BigInteger& n,
                               thread const BigInteger& r,
                               thread const BigInteger& r2,
                               uint32_t n_prime) {
    if (bigint_is_negative(exp)) {
        thread BigInteger exp_abs;
        bigint_abs_twos_complement(exp_abs, exp);
        mod_exp_montgomery_unsigned(result, base_inv, exp_abs, n, r, r2, n_prime);
        return;
    }
    mod_exp_montgomery_unsigned(result, base, exp, n, r, r2, n_prime);
}

// ============================================================================
// Kernel Functions
// ============================================================================

// Modular exponentiation kernel
kernel void modPowKernel(
    device const BigInteger* bases [[buffer(0)]],
    device const BigInteger* exps [[buffer(1)]],
    device const BigInteger* mods [[buffer(2)]],
    device const BigInteger* r_in [[buffer(3)]],
    device const BigInteger* r2_in [[buffer(4)]],
    device BigInteger* results [[buffer(5)]],
    constant uint& numLength [[buffer(6)]],
    constant uint& count [[buffer(7)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= count) return;

    // Copy data from device to thread memory
    thread BigInteger base = bases[id];
    thread BigInteger exp = exps[id];
    thread BigInteger mod = mods[id];
    thread BigInteger r = r_in[0];
    thread BigInteger r2 = r2_in[0];
    thread BigInteger result;

    uint32_t n_prime = montgomery_compute_n_prime(mod);

    mod_exp_montgomery_unsigned(result, base, exp, mod, r, r2, n_prime);

    // Copy result back to device memory
    results[id] = result;
}

// Modular exponentiation kernel (signed exponent with precomputed base inverse)
kernel void modPowSignedKernel(
    device const BigInteger* bases [[buffer(0)]],
    device const BigInteger* base_invs [[buffer(1)]],
    device const BigInteger* exps [[buffer(2)]],
    device const BigInteger* mods [[buffer(3)]],
    device const BigInteger* r_in [[buffer(4)]],
    device const BigInteger* r2_in [[buffer(5)]],
    device BigInteger* results [[buffer(6)]],
    constant uint& numLength [[buffer(7)]],
    constant uint& count [[buffer(8)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= count) return;

    // Copy data from device to thread memory
    thread BigInteger base = bases[id];
    thread BigInteger base_inv = base_invs[id];
    thread BigInteger exp = exps[id];
    thread BigInteger mod = mods[id];
    thread BigInteger r = r_in[0];
    thread BigInteger r2 = r2_in[0];
    thread BigInteger result;

    uint32_t n_prime = montgomery_compute_n_prime(mod);

    mod_exp_montgomery_signed(result, base, base_inv, exp, mod, r, r2, n_prime);

    // Copy result back to device memory
    results[id] = result;
}

// Batch modular exponentiation kernel
kernel void batchModPowKernel(
    device const BigInteger* bases [[buffer(0)]],
    device const BigInteger* exp [[buffer(1)]],
    device const BigInteger* mod [[buffer(2)]],
    device const BigInteger* r_in [[buffer(3)]],
    device const BigInteger* r2_in [[buffer(4)]],
    device BigInteger* results [[buffer(5)]],
    constant uint& numLength [[buffer(6)]],
    constant uint& count [[buffer(7)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= count) return;

    // Copy data from device to thread memory
    thread BigInteger base = bases[id];
    thread BigInteger exp_val = exp[0];
    thread BigInteger mod_val = mod[0];
    thread BigInteger r = r_in[0];
    thread BigInteger r2 = r2_in[0];
    thread BigInteger result;

    uint32_t n_prime = montgomery_compute_n_prime(mod_val);

    mod_exp_montgomery_unsigned(result, base, exp_val, mod_val, r, r2, n_prime);

    // Copy result back to device memory
    results[id] = result;
}

// Compute AffG Proof Tuple kernel
kernel void computeAffGProofTupleKernel(
    device const BigInteger* C [[buffer(0)]],
    device const BigInteger* N0 [[buffer(1)]],
    device const BigInteger* N0sq [[buffer(2)]],
    device const BigInteger* N1 [[buffer(3)]],
    device const BigInteger* N1sq [[buffer(4)]],
    device const BigInteger* rN0_in [[buffer(5)]],
    device const BigInteger* r2N0_in [[buffer(6)]],
    device const BigInteger* rN1_in [[buffer(7)]],
    device const BigInteger* r2N1_in [[buffer(8)]],
    device const BigInteger* C_inv_in [[buffer(9)]],
    device const BigInteger* onePlusN0_inv_in [[buffer(10)]],
    device const BigInteger* onePlusN1_inv_in [[buffer(11)]],
    device const BigInteger* alphas [[buffer(12)]],
    device const BigInteger* betasForN0 [[buffer(13)]],
    device const BigInteger* betasForN1 [[buffer(14)]],
    device const BigInteger* rs [[buffer(15)]],
    device const BigInteger* ss [[buffer(16)]],
    device BigInteger* Aj_results [[buffer(17)]],
    device BigInteger* Bj_results [[buffer(18)]],
    constant uint& numLength [[buffer(19)]],
    constant uint& kappa [[buffer(20)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= kappa) return;

    // Copy data from device to thread memory
    thread BigInteger C_val = C[0];
    thread BigInteger N0_val = N0[0];
    thread BigInteger N0sq_val = N0sq[0];
    thread BigInteger N1_val = N1[0];
    thread BigInteger N1sq_val = N1sq[0];
    thread BigInteger alpha = alphas[id];
    thread BigInteger betaForN0 = betasForN0[id];
    thread BigInteger betaForN1 = betasForN1[id];
    thread BigInteger r_val = rs[id];
    thread BigInteger s_val = ss[id];
    thread BigInteger rN0 = rN0_in[0];
    thread BigInteger r2N0 = r2N0_in[0];
    thread BigInteger rN1 = rN1_in[0];
    thread BigInteger r2N1 = r2N1_in[0];
    thread BigInteger C_inv = C_inv_in[0];
    thread BigInteger onePlusN0_inv = onePlusN0_inv_in[0];
    thread BigInteger onePlusN1_inv = onePlusN1_inv_in[0];
    thread BigInteger Aj;
    thread BigInteger Bj;

    uint32_t n0_prime = montgomery_compute_n_prime(N0sq_val);
    uint32_t n1_prime = montgomery_compute_n_prime(N1sq_val);

    thread BigInteger onePlusN0;
    thread BigInteger onePlusN1;
    thread BigInteger one;
    bigint_set_zero(one);
    one.data[0] = 1;
    bigint_add(onePlusN0, N0_val, one);
    bigint_add(onePlusN1, N1_val, one);

    thread BigInteger c_pow_alpha;
    thread BigInteger onePlusN0_pow_beta;
    thread BigInteger r_pow_n0;
    mod_exp_montgomery_signed(c_pow_alpha, C_val, C_inv, alpha, N0sq_val, rN0, r2N0, n0_prime);
    mod_exp_montgomery_signed(onePlusN0_pow_beta, onePlusN0, onePlusN0_inv, betaForN0, N0sq_val, rN0, r2N0, n0_prime);
    mod_exp_montgomery_unsigned(r_pow_n0, r_val, N0_val, N0sq_val, rN0, r2N0, n0_prime);

    thread BigInteger tmp;
    montgomery_mul_mod(tmp, c_pow_alpha, onePlusN0_pow_beta, N0sq_val, r2N0, n0_prime);
    montgomery_mul_mod(Aj, tmp, r_pow_n0, N0sq_val, r2N0, n0_prime);

    thread BigInteger onePlusN1_pow_beta;
    thread BigInteger s_pow_n1;
    mod_exp_montgomery_signed(onePlusN1_pow_beta, onePlusN1, onePlusN1_inv, betaForN1, N1sq_val, rN1, r2N1, n1_prime);
    mod_exp_montgomery_unsigned(s_pow_n1, s_val, N1_val, N1sq_val, rN1, r2N1, n1_prime);

    montgomery_mul_mod(Bj, onePlusN1_pow_beta, s_pow_n1, N1sq_val, r2N1, n1_prime);

    // Copy results back to device memory
    Aj_results[id] = Aj;
    Bj_results[id] = Bj;
}

// Compute Dec Proof Tuple kernel
kernel void computeDecProofTupleKernel(
    device const BigInteger* K [[buffer(0)]],
    device const BigInteger* N0 [[buffer(1)]],
    device const BigInteger* N0sq [[buffer(2)]],
    device const BigInteger* rN0_in [[buffer(3)]],
    device const BigInteger* r2N0_in [[buffer(4)]],
    device const BigInteger* K_inv_in [[buffer(5)]],
    device const BigInteger* onePlusN0_inv_in [[buffer(6)]],
    device const BigInteger* negAlphas [[buffer(7)]],
    device const BigInteger* betas [[buffer(8)]],
    device const BigInteger* rs [[buffer(9)]],
    device BigInteger* A_results [[buffer(10)]],
    constant uint& numLength [[buffer(11)]],
    constant uint& kappa [[buffer(12)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= kappa) return;

    // Copy data from device to thread memory
    thread BigInteger K_val = K[0];
    thread BigInteger N0_val = N0[0];
    thread BigInteger N0sq_val = N0sq[0];
    thread BigInteger negAlpha = negAlphas[id];
    thread BigInteger beta = betas[id];
    thread BigInteger r_val = rs[id];
    thread BigInteger rN0 = rN0_in[0];
    thread BigInteger r2N0 = r2N0_in[0];
    thread BigInteger K_inv = K_inv_in[0];
    thread BigInteger onePlusN0_inv = onePlusN0_inv_in[0];
    thread BigInteger A;

    uint32_t n0_prime = montgomery_compute_n_prime(N0sq_val);

    thread BigInteger onePlusN0;
    thread BigInteger one;
    bigint_set_zero(one);
    one.data[0] = 1;
    bigint_add(onePlusN0, N0_val, one);

    thread BigInteger k_pow_alpha;
    thread BigInteger onePlusN0_pow_beta;
    thread BigInteger r_pow_n0;
    // negAlphas should be precomputed on host as -alpha (non-negative magnitude)
    mod_exp_montgomery_signed(k_pow_alpha, K_val, K_inv, negAlpha, N0sq_val, rN0, r2N0, n0_prime);
    mod_exp_montgomery_signed(onePlusN0_pow_beta, onePlusN0, onePlusN0_inv, beta, N0sq_val, rN0, r2N0, n0_prime);
    mod_exp_montgomery_unsigned(r_pow_n0, r_val, N0_val, N0sq_val, rN0, r2N0, n0_prime);

    thread BigInteger tmp;
    montgomery_mul_mod(tmp, k_pow_alpha, onePlusN0_pow_beta, N0sq_val, r2N0, n0_prime);
    montgomery_mul_mod(A, tmp, r_pow_n0, N0sq_val, r2N0, n0_prime);

    // Copy result back to device memory
    A_results[id] = A;
}

// Modular inverse kernel (using Fermat's little theorem for prime moduli, or extended Euclidean algorithm for general cases)
kernel void modInverseKernel(
    device const BigInteger* values [[buffer(0)]],
    device const BigInteger* mods [[buffer(1)]],
    device const BigInteger* r_in [[buffer(2)]],
    device const BigInteger* r2_in [[buffer(3)]],
    device BigInteger* results [[buffer(4)]],
    constant uint& numLength [[buffer(5)]],
    constant uint& count [[buffer(6)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= count) return;

    // Copy data from device to thread memory
    thread BigInteger value = values[id];
    thread BigInteger mod = mods[id];
    thread BigInteger r = r_in[0];
    thread BigInteger r2 = r2_in[0];
    thread BigInteger result;

    // For prime moduli, use Fermat's little theorem: a^(m-2) mod m
    // For composite moduli, use extended Euclidean algorithm
    // Here we use Fermat's little theorem as an approximation
    uint32_t n_prime = montgomery_compute_n_prime(mod);

    // Compute m-2
    thread BigInteger m_minus_2;
    thread BigInteger one;
    bigint_set_zero(one);
    one.data[0] = 1;
    bigint_sub(m_minus_2, mod, one);
    bigint_sub(m_minus_2, m_minus_2, one);

    mod_exp_montgomery_unsigned(result, value, m_minus_2, mod, r, r2, n_prime);

    // Copy result back to device memory
    results[id] = result;
}

// Multiplication kernel
kernel void multiplyKernel(
    device const BigInteger* a [[buffer(0)]],
    device const BigInteger* b [[buffer(1)]],
    device uint32_t* results [[buffer(2)]],
    constant uint& numLength [[buffer(3)]],
    constant uint& count [[buffer(4)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= count) return;

    // Copy data from device to thread memory
    thread BigInteger a_val = a[id];
    thread BigInteger b_val = b[id];
    thread DoubleBigInteger result;

    // Full DOUBLE_BIGINT_SIZE-word product
    for (uint i = 0; i < DOUBLE_BIGINT_SIZE; i++) {
        result.data[i] = 0;
    }
    for (uint i = 0; i < BIGINT_SIZE; i++) {
        if (b_val.data[i] != 0) {
            uint64_t carry = 0;
            for (uint j = 0; j < BIGINT_SIZE; j++) {
                uint idx = i + j;
                if (idx < DOUBLE_BIGINT_SIZE) {
                    uint64_t prod = (uint64_t)a_val.data[j] * (uint64_t)b_val.data[i] + result.data[idx] + carry;
                    result.data[idx] = (uint32_t)prod;
                    carry = prod >> 32;
                }
            }
            uint k = BIGINT_SIZE;
            while (carry > 0 && i + k < DOUBLE_BIGINT_SIZE) {
                uint64_t sum = result.data[i + k] + carry;
                result.data[i + k] = (uint32_t)sum;
                carry = sum >> 32;
                k++;
            }
        }
    }

    // Copy result back to device memory (flat array)
    uint baseIndex = id * DOUBLE_BIGINT_SIZE;
    for (uint k = 0; k < DOUBLE_BIGINT_SIZE; k++) {
        results[baseIndex + k] = result.data[k];
    }
}

// Batch modular exponentiation with different exponents kernel
kernel void batchModPowDifferentExpKernel(
    device const BigInteger* bases [[buffer(0)]],
    device const BigInteger* exps [[buffer(1)]],
    device const BigInteger* mods [[buffer(2)]],
    device const BigInteger* r_in [[buffer(3)]],
    device const BigInteger* r2_in [[buffer(4)]],
    device BigInteger* results [[buffer(5)]],
    constant uint& numLength [[buffer(6)]],
    constant uint& count [[buffer(7)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= count) return;

    // Copy data from device to thread memory
    thread BigInteger base = bases[id];
    thread BigInteger exp = exps[id];
    thread BigInteger mod = mods[id];
    thread BigInteger r = r_in[0];
    thread BigInteger r2 = r2_in[0];
    thread BigInteger result;

    uint32_t n_prime = montgomery_compute_n_prime(mod);

    mod_exp_montgomery_unsigned(result, base, exp, mod, r, r2, n_prime);

    // Copy result back to device memory
    results[id] = result;
}

// Batch modular exponentiation with different exponents (signed exponent with precomputed base inverse)
kernel void batchModPowDifferentExpSignedKernel(
    device const BigInteger* bases [[buffer(0)]],
    device const BigInteger* base_invs [[buffer(1)]],
    device const BigInteger* exps [[buffer(2)]],
    device const BigInteger* mods [[buffer(3)]],
    device const BigInteger* r_in [[buffer(4)]],
    device const BigInteger* r2_in [[buffer(5)]],
    device BigInteger* results [[buffer(6)]],
    constant uint& numLength [[buffer(7)]],
    constant uint& count [[buffer(8)]],
    uint id [[thread_position_in_grid]])
{
    if (id >= count) return;

    // Copy data from device to thread memory
    thread BigInteger base = bases[id];
    thread BigInteger base_inv = base_invs[id];
    thread BigInteger exp = exps[id];
    thread BigInteger mod = mods[id];
    thread BigInteger r = r_in[0];
    thread BigInteger r2 = r2_in[0];
    thread BigInteger result;

    uint32_t n_prime = montgomery_compute_n_prime(mod);

    mod_exp_montgomery_signed(result, base, base_inv, exp, mod, r, r2, n_prime);

    // Copy result back to device memory
    results[id] = result;
}
