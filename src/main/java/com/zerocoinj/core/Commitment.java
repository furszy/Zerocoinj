// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core;

import com.zerocoinj.core.context.IntegerGroupParams;
import com.zerocoinj.core.context.ZerocoinContext;
import com.zerocoinj.utils.ZUtils;
import org.spongycastle.util.BigIntegers;

import java.math.BigInteger;
import java.util.Objects;

public class Commitment {

    // We use a SHA256 hash for our PoK challenges. Update the following
    // if we ever change hash functions.
    public static final int COMMITMENT_EQUALITY_CHALLENGE_SIZE = 256;

    // A 512-bit security parameter for the statistical ZK PoK.
    public static final int COMMITMENT_EQUALITY_SECMARGIN = 512;

    private BigInteger commitmentValue;
    private BigInteger randomness;
    private BigInteger content;

    public Commitment(BigInteger content,BigInteger commitmentValue, BigInteger randomness) {
        this.commitmentValue = commitmentValue;
        this.randomness = randomness;
        this.content = content;
    }

    public Commitment(BigInteger content, IntegerGroupParams params){
        this.content = content;
        // Generate a random number "r" in the range 0...{q-1}
        this.randomness = BigIntegers.createRandomInRange(BigInteger.ZERO, params.getGroupOrder(), ZerocoinContext.getSecureRandom());
        // Manually compute a Pedersen commitment to the content "s" under randomness "r"
        // C = g^s * h^r mod p
        this.commitmentValue =
                params.getG().modPow(this.content,params.getModulus()).multiply(
                        params.getH().modPow(this.randomness, params.getModulus())).mod(params.getModulus());
    }

    public Commitment(BigInteger content, BigInteger randomness, IntegerGroupParams params) {
        this.randomness = randomness;
        this.content = content;
        // Manually compute a Pedersen commitment to the content "s" under randomness "r"
        // C = g^s * h^r mod p
        this.commitmentValue =
                params.getG().modPow(this.content,params.getModulus()).multiply(
                        params.getH().modPow(this.randomness, params.getModulus())).mod(params.getModulus());
    }

    public BigInteger getCommitmentValue() {
        return commitmentValue;
    }

    public BigInteger getRandomness() {
        return randomness;
    }



    public BigInteger getContent() {
        return content;
    }

    @Override
    public String toString() {
        return "Commitment{\n" +
                "content DEC=" + content.toString() +
                "\n, commitmentValue DEC=" + commitmentValue.toString() +
                ",\n randomness DEC=" + randomness.toString() +
                "\n }";
    }


    public byte[] serialize() {
        return ZUtils.serializeBigInteger(getCommitmentValue());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Commitment that = (Commitment) o;
        return ZUtils.equals(commitmentValue, that.commitmentValue) &&
                ZUtils.equals(randomness, that.randomness) &&
                ZUtils.equals(content, that.content);
    }

    @Override
    public int hashCode() {

        return Objects.hash(commitmentValue, randomness, content);
    }
}
