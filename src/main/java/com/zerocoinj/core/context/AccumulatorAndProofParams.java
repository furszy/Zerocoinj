// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core.context;

import java.math.BigInteger;

public class AccumulatorAndProofParams {

    /**
     * Modulus used for the accumulator.
     * Product of two safe primes who's factorization is unknown.
     */
    BigInteger accumulatorModulus;

    /**
     * The initial value for the accumulator
     * A random Quadratic residue mod n thats not 1
     */
    BigInteger accumulatorBase;

    /**
     * Lower bound on the value for committed coin.
     * Required by the accumulator proof.
     */
    BigInteger minCoinValue;

    /**
     * Upper bound on the value for a comitted coin.
     * Required by the accumulator proof.
     */
    BigInteger maxCoinValue;

    /**
     * The second of two groups used to form a commitment to
     * a coin (which it self is a commitment to a serial number).
     * This one differs from serialNumberSokCommitment due to
     * restrictions from Camenisch and Lysyanskaya's paper.
     */
    IntegerGroupParams accumulatorPoKCommitmentGroup;

    /**
     * Hidden order quadratic residue group mod N.
     * Used in the accumulator proof.
     */
    IntegerGroupParams accumulatorQRNCommitmentGroup;

    /**
     * Security parameter.
     * Bit length of the challenges used in the accumulator proof.
     */
    int k_prime;

    /**
     * Security parameter.
     * The statistical zero-knowledgeness of the accumulator proof.
     */
    int k_dprime;

    private boolean isInitialized;

    /** @brief Construct a set of Zerocoin parameters from a modulus "N".
     * @param N                A trusted RSA modulus
     * @param securityLevel    A security level expressed in symmetric bits (default 80)
     *
     * Allocates and derives a set of Zerocoin parameters from
     * a trustworthy RSA modulus "N". This routine calculates all
     * of the remaining parameters (group descriptions etc.) from N
     * using a verifiable, deterministic procedure.
     *
     * Note: this constructor makes the fundamental assumption that "N"
     * encodes a valid RSA-style modulus of the form "e1 * e2" where
     * "e1" and "e2" are safe primes. The factors "e1", "e2" MUST NOT
     * be known to any party, or the security of Zerocoin is
     * compromised. The integer "N" must be a MINIMUM of 1024
     * in length. 3072 bits is strongly recommended.
     **/
    public AccumulatorAndProofParams(){
        isInitialized = true;
    }

    public BigInteger getAccumulatorModulus() {
        return accumulatorModulus;
    }

    public BigInteger getAccumulatorBase() {
        return accumulatorBase;
    }

    public BigInteger getMinCoinValue() {
        return minCoinValue;
    }

    public BigInteger getMaxCoinValue() {
        return maxCoinValue;
    }

    public IntegerGroupParams getAccumulatorPoKCommitmentGroup() {
        return accumulatorPoKCommitmentGroup;
    }

    public IntegerGroupParams getAccumulatorQRNCommitmentGroup() {
        return accumulatorQRNCommitmentGroup;
    }

    public int getK_prime() {
        return k_prime;
    }

    public int getK_dprime() {
        return k_dprime;
    }

    @Override
    public String toString() {
        return "AccumulatorAndProofParams{" +
                "accumulatorModulus=" + accumulatorModulus +
                ", accumulatorBase=" + accumulatorBase +
                ", minCoinValue=" + minCoinValue +
                ", maxCoinValue=" + maxCoinValue +
                ", accumulatorPoKCommitmentGroup=" + accumulatorPoKCommitmentGroup +
                ", accumulatorQRNCommitmentGroup=" + accumulatorQRNCommitmentGroup +
                ", k_prime=" + k_prime +
                ", k_dprime=" + k_dprime +
                '}';
    }

    public boolean isInitialized() {
        return isInitialized;
    }

}
