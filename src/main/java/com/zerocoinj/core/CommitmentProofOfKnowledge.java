// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core;

import com.google.common.base.Preconditions;
import com.zerocoinj.core.context.IntegerGroupParams;
import com.zerocoinj.utils.ZUtils;
import org.pivxj.core.Message;
import org.pivxj.core.NetworkParameters;
import org.pivxj.core.ProtocolException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Objects;

import static com.zerocoinj.core.Commitment.COMMITMENT_EQUALITY_CHALLENGE_SIZE;
import static com.zerocoinj.core.Commitment.COMMITMENT_EQUALITY_SECMARGIN;
import static com.zerocoinj.core.context.ZerocoinDefines.ZEROCOIN_COMMITMENT_EQUALITY_PROOF;
import static com.zerocoinj.utils.ZUtils.*;
import static java.lang.Math.max;

/**
 * Proof that two commitments open to the same value.
 */
public class CommitmentProofOfKnowledge extends Message {

    private static final Logger log = LoggerFactory.getLogger(CommitmentProofOfKnowledge.class);

    private final IntegerGroupParams aParams, bParams;

    private BigInteger S1, S2, S3, challenge;

    public CommitmentProofOfKnowledge(NetworkParameters params, final IntegerGroupParams aParams, final IntegerGroupParams bParams) {
        super(params);
        this.aParams = aParams;
        this.bParams = bParams;
    }

    /** Generates a proof that two commitments, a and b, open to the same value.
     *
     * @param aParams the IntegerGroup for commitment a
     * @param bParams the IntegerGroup for commitment b
     * @param a the first commitment
     * @param b the second commitment
     */
    public CommitmentProofOfKnowledge(final IntegerGroupParams aParams, final IntegerGroupParams bParams, final Commitment a, final Commitment b){
        this.aParams = aParams;
        this.bParams = bParams;

        BigInteger r1, r2, r3;

        // First: make sure that the two commitments have the
        // same contents.
        if (ZUtils.equals(a.getCommitmentValue(), b.getCommitmentValue())) {
            throw new RuntimeException("Both commitments must contain the same value");
        }

        // Select three random values "r1, r2, r3" in the range 0 to (2^l)-1 where l is:
        // length of challenge value + max(modulus 1, modulus 2, order 1, order 2) + margin.
        // We set "margin" to be a relatively generous  security parameter.
        //
        // We choose these large values to ensure statistical zero knowledge.
        int randomSize = COMMITMENT_EQUALITY_CHALLENGE_SIZE + COMMITMENT_EQUALITY_SECMARGIN +
                max(max(this.aParams.getModulus().bitLength(), this.bParams.getModulus().bitLength()),
                max(this.aParams.getGroupOrder().bitLength(), this.bParams.getGroupOrder().bitLength()));

        BigInteger maxRange = (ZUtils.BIGNUM_2.pow(randomSize)).subtract(BigInteger.ONE);


        r1 = ZUtils.random(maxRange);
        r2 = ZUtils.random(maxRange);
        r3 = ZUtils.random(maxRange);

        // Generate two random, ephemeral commitments "T1, T2"
        // of the form:
        // T1 = g1^r1 * h1^r2 mod p1
        // T2 = g2^r1 * h2^r3 mod p2
        //
        // Where (g1, h1, p1) are from "aParams" and (g2, h2, p2) are from "bParams".
        BigInteger T1 = mul_mod(
                this.aParams.getG().modPow(r1, this.aParams.getModulus()),
                this.aParams.getH().modPow(r2, this.aParams.getModulus()),
                this.aParams.getModulus()
        );

        BigInteger T2 = mul_mod(
                this.bParams.getG().modPow(r1, this.bParams.getModulus()),
                this.bParams.getH().modPow(r3, this.bParams.getModulus()),
                this.bParams.getModulus()
        );

        // Now hash commitment "A" with commitment "B" as well as the
        // parameters and the two ephemeral commitments "T1, T2" we just generated
        this.challenge = calculateChallenge(a.getCommitmentValue(), b.getCommitmentValue(), T1, T2);

        // If challenge is negative, let's turn it
        // If challenge is negative, let's turn it
        // TODO: I added this..
        if (isNegative(this.challenge)){
            this.challenge = this.challenge.negate();
        }

        //System.out.println("CommitmentPoK Challenge: " + challenge);

        // Let "m" be the contents of the commitments "A, B". We have:
        // A =  g1^m  * h1^x  mod p1
        // B =  g2^m  * h2^y  mod p2
        // T1 = g1^r1 * h1^r2 mod p1
        // T2 = g2^r1 * h2^r3 mod p2
        //
        // Now compute:
        //  S1 = r1 + (m * challenge)   -- note, not modular arithmetic
        //  S2 = r2 + (x * challenge)   -- note, not modular arithmetic
        //  S3 = r3 + (y * challenge)   -- note, not modular arithmetic
        this.S1 = r1.add(a.getContent().multiply(this.challenge));
        this.S2 = r2.add(a.getRandomness().multiply(this.challenge));
        this.S3 = r3.add(b.getRandomness().multiply(this.challenge));

        // We're done. The proof is S1, S2, S3 and "challenge", all of which
        // are stored in member variables.
    }

    private BigInteger calculateChallenge(BigInteger a, BigInteger b, BigInteger commitOne, BigInteger commitTwo) {
        try {
            HashWriter hashWriter = new HashWriter();

            // Hash together the following elements:
            // * A string identifying the proof
            // * Commitment A
            // * Commitment B
            // * Ephemeral commitment T1
            // * Ephemeral commitment T2
            // * A serialized instance of the commitment A parameters
            // * A serialized instance of the commitment B parameters

            String separatorStr = "||";
            hashWriter.write(ZEROCOIN_COMMITMENT_EQUALITY_PROOF)
                    .write(commitOne)
                    .write(separatorStr)
                    .write(commitTwo)
                    .write(separatorStr)
                    .write(a)
                    .write(separatorStr)
                    .write(b)
                    .write(separatorStr)
                    .write(aParams)
                    .write(separatorStr)
                    .write(bParams);

            // Convert the SHA256 result into a Bignum
            // Note that if we ever change the size of the hash function we will have
            // to update COMMITMENT_EQUALITY_CHALLENGE_SIZE appropriately!
            return hashWriter.toUint256(null,true);
        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }


    public boolean verify(BigInteger A, BigInteger B) {

        // Compute the maximum range of S1, S2, S3 and verify that the given values are
        // in a correct range. This might be an unnecessary check.
        int maxSize = 64 * (COMMITMENT_EQUALITY_CHALLENGE_SIZE + COMMITMENT_EQUALITY_SECMARGIN +
                max(max(this.aParams.getModulus().bitLength(), this.bParams.getModulus().bitLength()),
                max(this.aParams.getGroupOrder().bitLength(), this.bParams.getGroupOrder().bitLength())));

        if (this.S1.bitLength() > maxSize ||
                this.S2.bitLength() > maxSize ||
                this.S3.bitLength() > maxSize ||
                isNegative(this.S1) ||
                isNegative(this.S2) ||
                isNegative(this.S3) ||
                isNegative(this.challenge) ||
                isGreaterThan(this.challenge , ( (ZUtils.BIGNUM_2.pow(COMMITMENT_EQUALITY_CHALLENGE_SIZE)) .subtract(BigInteger.ONE)))) {
            // Invalid inputs. Reject.
            log.info("Verify:: Invalid inputs");
            return false;
        }

        // Compute T1 = g1^S1 * h1^S2 * inverse(A^{challenge}) mod p1

        BigInteger T1 = mul_mod(A.modPow(this.challenge, aParams.getModulus()).modInverse(aParams.getModulus()),
                mul_mod(aParams.getG().modPow(S1, aParams.getModulus()), aParams.getH().modPow(S2, aParams.getModulus()), aParams.getModulus())
                , aParams.getModulus());


        // Compute T2 = g2^S1 * h2^S3 * inverse(B^{challenge}) mod p2
        BigInteger firstPartT2 = B.modPow(this.challenge, this.bParams.getModulus()).modInverse(bParams.getModulus());
        BigInteger secondPartT2 = mul_mod(this.bParams.getG().modPow(S1, bParams.getModulus()),bParams.getH().modPow(S3, bParams.getModulus()), bParams.getModulus());
        BigInteger T2 = mul_mod(firstPartT2, secondPartT2, bParams.getModulus());

        // Hash T1 and T2 along with all of the public parameters
        BigInteger computedChallenge = calculateChallenge(A, B, T1, T2);

        // If challenge is negative, let's turn it
        if (isNegative(computedChallenge)){
            computedChallenge = computedChallenge.negate();
        }

        // Return success if the computed challenge matches the incoming challenge
        return ZUtils.equals(computedChallenge , this.challenge );
    }

    public IntegerGroupParams getaParams() {
        return aParams;
    }

    public IntegerGroupParams getbParams() {
        return bParams;
    }

    public BigInteger getS1() {
        return S1;
    }

    public BigInteger getS2() {
        return S2;
    }

    public BigInteger getS3() {
        return S3;
    }

    public BigInteger getChallenge() {
        return challenge;
    }


    public static CommitmentProofOfKnowledge parse(
            NetworkParameters params,
            final IntegerGroupParams aParams,
            final IntegerGroupParams bParams,
            byte[] payload,
            int cursor,
            boolean retainMode
    ) {
        CommitmentProofOfKnowledge cPoK = new CommitmentProofOfKnowledge(params, aParams, bParams);
        // Add protocol if i need it in the future
        //sok.protocolVersion = protocolVersion;
        cPoK.payload = payload;
        cPoK.cursor = cPoK.offset = cursor;
        cPoK.length = payload.length;

        cPoK.parse();

        if (cPoK.length == UNKNOWN_LENGTH) {
            Preconditions.checkState(false, "Length field has not been set in constructor for %s after parse.", cPoK.getClass().getSimpleName());
        }

        if (retainMode) {
            cPoK.payload = null;
        }
        return cPoK;
    }

    @Override
    protected void parse() throws ProtocolException {
        S1 = readBignum();
        S2 = readBignum();
        S3 = readBignum();
        challenge = readBignum();
    }

    @Override
    public byte[] bitcoinSerialize() {
        ByteArrayOutputStream buffer = null;
        try {
            buffer = new ByteArrayOutputStream();
            ZUtils.serializeBigInteger(buffer,S1);
            ZUtils.serializeBigInteger(buffer,S2);
            ZUtils.serializeBigInteger(buffer,S3);
            ZUtils.serializeBigInteger(buffer,challenge);
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize CommitmentPoK", e);
        } finally {
            try {
                if (buffer != null) {
                    buffer.close();
                }
            } catch (IOException e) {
                // nothing
            }
        }
    }

    @Override
    public String toString() {
        return "CommitmentProofOfKnowledge{" +
                "aParams=" + aParams +
                "\n, bParams=" + bParams +
                "\n, S1=" + S1 +
                "\n, S2=" + S2 +
                "\n, S3=" + S3 +
                "\n, challenge=" + challenge +
                '}';
    }

    public int getCursor() {
        return this.cursor;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CommitmentProofOfKnowledge that = (CommitmentProofOfKnowledge) o;
        return ZUtils.equals(S1, that.S1) &&
                ZUtils.equals(S2, that.S2) &&
                ZUtils.equals(S3, that.S3) &&
                ZUtils.equals(challenge, that.challenge);
    }

    @Override
    public int hashCode() {
        return Objects.hash(S1, S2, S3, challenge);
    }
}
