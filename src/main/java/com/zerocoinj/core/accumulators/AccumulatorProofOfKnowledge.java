// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core.accumulators;

import com.google.common.base.Preconditions;
import com.zerocoinj.core.Commitment;
import com.zerocoinj.core.HashWriter;
import com.zerocoinj.core.context.AccumulatorAndProofParams;
import com.zerocoinj.core.context.IntegerGroupParams;
import com.zerocoinj.core.context.ZerocoinContext;
import com.zerocoinj.utils.ZUtils;
import org.pivxj.core.Message;
import org.pivxj.core.NetworkParameters;
import org.pivxj.core.ProtocolException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Objects;

import static com.zerocoinj.utils.ZUtils.*;

/**
 * A prove that a value inside the commitment commitmentToCoin is in an accumulator a.
 */
public class AccumulatorProofOfKnowledge extends Message {

    private AccumulatorAndProofParams zParams;

    /* Return values for proof */
    public BigInteger C_e;
    public BigInteger C_u;
    public BigInteger C_r;

    public BigInteger st_1;
    public BigInteger st_2;
    public BigInteger st_3;

    public BigInteger t_1;
    public BigInteger t_2;
    public BigInteger t_3;
    public BigInteger t_4;

    public BigInteger s_alpha;
    public BigInteger s_beta;
    public BigInteger s_zeta;
    public BigInteger s_sigma;
    public BigInteger s_eta;
    public BigInteger s_epsilon;
    public BigInteger s_delta;
    public BigInteger s_xi;
    public BigInteger s_phi;
    public BigInteger s_gamma;
    public BigInteger s_psi;

    public AccumulatorProofOfKnowledge(NetworkParameters params) {
        super(params);
    }

    /**
     * Generates a proof that a commitment to a coin c was accumulated
     * @param p  Cryptographic parameters
     * @param commitmentToCoin commitment containing the coin we want to prove is accumulated
     * @param witness The witness to the accumulation of the coin
     * @param a
     */
    public AccumulatorProofOfKnowledge(final AccumulatorAndProofParams p, final Commitment commitmentToCoin, final AccumulatorWitness witness, Accumulator a){
        this.zParams = p;

        // Params accumulator modulus
        BigInteger pAccModulus = zParams.getAccumulatorModulus();
        // Params Accumulator Commitment Group
        IntegerGroupParams pAccPoKCommitmentGroup = zParams.getAccumulatorPoKCommitmentGroup();
        // Params Accumulator Quadratic Residue group mod N
        IntegerGroupParams accumulatorQRNCommitmentGroup = zParams.getAccumulatorQRNCommitmentGroup();

        BigInteger sg = pAccPoKCommitmentGroup.getG();
        BigInteger sh = pAccPoKCommitmentGroup.getH();

        BigInteger g_n = accumulatorQRNCommitmentGroup.getG();
        BigInteger h_n = accumulatorQRNCommitmentGroup.getH();

        BigInteger e = commitmentToCoin.getContent();
        BigInteger r = commitmentToCoin.getRandomness();

        BigInteger aM_4 = pAccModulus.divide(BIGNUM_4);

        BigInteger r_1 = random(aM_4);
        BigInteger r_2 = random(aM_4);
        BigInteger r_3 = random(aM_4);

        this.C_e = g_n.modPow(e, pAccModulus).multiply(h_n.modPow(r_1, pAccModulus));
        this.C_u = witness.getValue().multiply(h_n.modPow(r_2, pAccModulus));
        this.C_r = g_n.modPow(r_2, pAccModulus).multiply(h_n.modPow(r_3, pAccModulus));

        BigInteger range = zParams.getMaxCoinValue().multiply(BIGNUM_2.pow(zParams.getK_prime() + zParams.getK_dprime()));

        BigInteger r_alpha = random(range);

        if(isZero( random(BIGNUM_3).mod(BIGNUM_2) )) {
            r_alpha = r_alpha.negate();
        }

        BigInteger r_gamma = random(pAccPoKCommitmentGroup.getModulus());
        BigInteger r_phi = random(pAccPoKCommitmentGroup.getModulus());
        BigInteger r_psi = random(pAccPoKCommitmentGroup.getModulus());
        BigInteger r_sigma = random(pAccPoKCommitmentGroup.getModulus());
        BigInteger r_xi = random(pAccPoKCommitmentGroup.getModulus());

        BigInteger r_epsilon =  random(
                (aM_4).multiply(BIGNUM_2.pow(zParams.getK_prime() + zParams.getK_dprime()))
        );
        if(isZero(random(BIGNUM_3).mod(BIGNUM_2))) {
            r_epsilon = r_epsilon.negate();
        }

        BigInteger r_eta = random(
                (aM_4).multiply(BIGNUM_2.pow(zParams.getK_prime() + zParams.getK_dprime()))
        );
        if(isZero(random(BIGNUM_3).mod(BIGNUM_2))) {
            r_eta = r_eta.negate();
        }

        BigInteger r_zeta = random(
                (aM_4).multiply(BIGNUM_2.pow(zParams.getK_prime() + zParams.getK_dprime()))
        );
        if(isZero(random(BIGNUM_3).mod(BIGNUM_2))) {
            r_zeta = r_zeta.negate();
        }

        BigInteger r_beta = random(
                (aM_4).multiply(pAccPoKCommitmentGroup.getModulus().multiply(BIGNUM_2.pow(zParams.getK_prime() + zParams.getK_dprime())))
        );
        if(isZero(random(BIGNUM_3).mod(BIGNUM_2))) {
            r_beta = r_beta.negate();
        }

        BigInteger r_delta = random(
                (aM_4).multiply(pAccPoKCommitmentGroup.getModulus().multiply(BIGNUM_2.pow(zParams.getK_prime() + zParams.getK_dprime())))
        );
        if(isZero(random(BIGNUM_3).mod(BIGNUM_2))) {
            r_delta = r_delta.negate();
        }

        this.st_1 = (
                sg.modPow(r_alpha, pAccPoKCommitmentGroup.getModulus()).multiply(
                        sh.modPow(r_phi, pAccPoKCommitmentGroup.getModulus()))
        ).mod(pAccPoKCommitmentGroup.getModulus());

        this.st_2 =
                (((commitmentToCoin.getCommitmentValue().multiply(sg.modInverse(pAccPoKCommitmentGroup.getModulus())))
                        .modPow(r_gamma, pAccPoKCommitmentGroup.getModulus()))
                        .multiply(sh.modPow(r_psi, pAccPoKCommitmentGroup.getModulus())))
                        .mod(pAccPoKCommitmentGroup.getModulus());

        this.st_3 = (
                (sg.multiply(commitmentToCoin.getCommitmentValue())).modPow(r_sigma, pAccPoKCommitmentGroup.getModulus()).multiply(sh.modPow(r_xi, pAccPoKCommitmentGroup.getModulus()))).mod(pAccPoKCommitmentGroup.getModulus());

        this.t_1 = (h_n.modPow(r_zeta, pAccModulus).multiply(g_n.modPow(r_epsilon, pAccModulus))).mod(pAccModulus);
        this.t_2 = (h_n.modPow(r_eta, pAccModulus).multiply(g_n.modPow(r_alpha, pAccModulus))) .mod(pAccModulus);
        this.t_3 = (C_u.modPow(r_alpha, pAccModulus).multiply ((h_n.modInverse(pAccModulus)).modPow(r_beta, pAccModulus))) .mod(pAccModulus);
        this.t_4 = (C_r.modPow(r_alpha, pAccModulus).multiply ((h_n.modInverse(pAccModulus)).modPow(r_delta, pAccModulus)) .multiply ((g_n.modInverse(pAccModulus)).modPow(r_beta, pAccModulus))) .mod(pAccModulus);

        HashWriter hasher = new HashWriter();
        hasher.write(zParams)
                .write(sg)
                .write(sh)
                .write(g_n)
                .write(h_n)
                .write(commitmentToCoin.getCommitmentValue())
                .write(C_e)
                .write(C_u)
                .write(C_r)
                .write(st_1)
                .write(st_2)
                .write(st_3)
                .write(t_1)
                .write(t_2)
                .write(t_3)
                .write(t_4);

        //According to the proof, this hash should be of length k_prime bits.  It is currently greater than that, which should not be a problem, but we should check this.
        BigInteger c = hasher.toUint256(null,true);

        // This should not be negative..
        if (isNegative(c))
            c = c.negate();

        this.s_alpha = r_alpha.subtract(c.multiply(e));
        this.s_beta = r_beta.subtract(c.multiply(r_2).multiply(e));
        this.s_zeta = r_zeta .subtract(c.multiply(r_3));
        this.s_sigma = r_sigma.subtract(c.multiply((e.add(BIGNUM_1)).modInverse(pAccPoKCommitmentGroup.getGroupOrder())));
        this.s_eta = r_eta .subtract(c.multiply(r_1));
        this.s_epsilon = r_epsilon .subtract( c.multiply(r_2));
        this.s_delta = r_delta .subtract(c.multiply(r_3.multiply(e)));
        this.s_xi = r_xi.add( c.multiply(r.multiply((e.add(BIGNUM_1)).modInverse(pAccPoKCommitmentGroup.getGroupOrder()))));
        this.s_phi = (r_phi.subtract(c.multiply(r))) .mod( pAccPoKCommitmentGroup.getGroupOrder());
        this.s_gamma = r_gamma .subtract( c.multiply((e.subtract(BIGNUM_1)).modInverse(pAccPoKCommitmentGroup.getGroupOrder())));
        this.s_psi = r_psi .add( c.multiply(r.multiply((e.subtract(BIGNUM_1)).modInverse(pAccPoKCommitmentGroup.getGroupOrder()))));

    }

    /**
     * Verifies that a commitment c is accumulated in accumulator a
     * @return true if 'a' commitment 'c' is accumulated in accumulator a
     */
    public boolean verify(final Accumulator a, BigInteger valueOfCommitmentToCoin){

        IntegerGroupParams pAccPoKCommitmentGroup = zParams.getAccumulatorPoKCommitmentGroup();
        IntegerGroupParams accumulatorQRNCommitmentGroup = zParams.getAccumulatorQRNCommitmentGroup();
        BigInteger accModulus = zParams.getAccumulatorModulus();

        BigInteger sg = pAccPoKCommitmentGroup.getG();
        BigInteger sh = pAccPoKCommitmentGroup.getH();

        BigInteger g_n = accumulatorQRNCommitmentGroup.getG();
        BigInteger h_n = accumulatorQRNCommitmentGroup.getH();

        //According to the proof, this hash should be of length k_prime bits.  It is currently greater than that, which should not be a problem, but we should check this.
        HashWriter hasher = new HashWriter();
        hasher.write(zParams)
                .write(sg)
                .write(sh)
                .write(g_n)
                .write(h_n)
                .write(valueOfCommitmentToCoin)
                .write(C_e)
                .write(C_u)
                .write(C_r)
                .write(st_1)
                .write(st_2)
                .write(st_3)
                .write(t_1)
                .write(t_2)
                .write(t_3)
                .write(t_4);

        BigInteger c = hasher.toUint256(null,true); //this hash should be of length k_prime bits

        // For some X reason this cannot be null..
        if (isNegative(c)){
            c = c.negate();
        }

        BigInteger st_1_prime = (
                valueOfCommitmentToCoin.modPow(c, pAccPoKCommitmentGroup.getModulus()).multiply(
                        sg.modPow(s_alpha, pAccPoKCommitmentGroup.getModulus())).multiply(
                        sh.modPow(s_phi, pAccPoKCommitmentGroup.getModulus()))
        ) .mod(pAccPoKCommitmentGroup.getModulus());

        BigInteger st_2_prime = ( (sg.modPow(c, pAccPoKCommitmentGroup.getModulus()) ) .multiply (
                (valueOfCommitmentToCoin .multiply( sg.modInverse(pAccPoKCommitmentGroup.getModulus())).modPow(s_gamma, pAccPoKCommitmentGroup.getModulus()))) .multiply(
                        sh.modPow(s_psi, pAccPoKCommitmentGroup.getModulus())) )
                .mod(pAccPoKCommitmentGroup.getModulus());
        BigInteger st_3_prime = (
                ( sg.modPow(c, pAccPoKCommitmentGroup.getModulus()) ) .multiply ( (sg .multiply(valueOfCommitmentToCoin) ).modPow(s_sigma, pAccPoKCommitmentGroup.getModulus()) ) .multiply( sh.modPow(s_xi, pAccPoKCommitmentGroup.getModulus())) ) .mod(pAccPoKCommitmentGroup.getModulus());

        BigInteger t_1_prime = (
                ( C_r.modPow(c, accModulus) ) .multiply ( h_n.modPow(s_zeta, accModulus) ) .multiply ( g_n.modPow(s_epsilon, accModulus) )
        ).mod (accModulus);
        BigInteger t_2_prime = (
                ( C_e.modPow(c, accModulus) ) .multiply ( h_n.modPow(s_eta, accModulus) ) .multiply (g_n.modPow(s_alpha, accModulus))
        ) .mod(accModulus);
        BigInteger t_3_prime = (
                ( (a.getValue()).modPow(c, accModulus) ) .multiply ( C_u.modPow(s_alpha, accModulus) ) .multiply ( ((h_n.modInverse(accModulus)).modPow(s_beta, accModulus)) )
        ) .mod(accModulus);
        BigInteger t_4_prime = (
                ( C_r.modPow(s_alpha, accModulus) ) .multiply ((h_n.modInverse(accModulus)).modPow(s_delta, accModulus)) .multiply ( ((g_n.modInverse(accModulus)).modPow(s_beta, accModulus)) )
        ) .mod(accModulus);

        boolean result_st1 = ZUtils.equals(st_1 , st_1_prime);
        boolean result_st2 = ZUtils.equals(st_2 , st_2_prime);
        boolean result_st3 = ZUtils.equals(st_3 , st_3_prime);

        boolean result_t1 = ZUtils.equals(t_1 , t_1_prime);
        boolean result_t2 = ZUtils.equals(t_2 , t_2_prime);
        boolean result_t3 = ZUtils.equals(t_3 , t_3_prime);
        boolean result_t4 = ZUtils.equals(t_4 , t_4_prime);

        boolean result_range = (
                ZUtils.isGreaterOrEqualThan(s_alpha , (zParams.getMaxCoinValue() .multiply ( BIGNUM_2.pow(zParams.getK_prime() + zParams.getK_dprime() + 1))).negate()))
                &&
                ZUtils.isLessOrEqualThan(
                        s_alpha,
                        zParams.getMaxCoinValue() .multiply (BIGNUM_2.pow(zParams.getK_prime() + zParams.getK_dprime() + 1))
                );


        return result_st1 && result_st2 && result_st3 && result_t1 && result_t2 && result_t3 && result_t4 && result_range;

    }


    public static AccumulatorProofOfKnowledge parse(NetworkParameters params, ZerocoinContext zerocoinContext, byte[] payload, int cursor, boolean retainMode) {
        AccumulatorProofOfKnowledge accPoK = new AccumulatorProofOfKnowledge(params);
        // Add protocol if i need it in the future
        //sok.protocolVersion = protocolVersion;
        accPoK.zParams = zerocoinContext.accumulatorParams;
        accPoK.payload = payload;
        accPoK.cursor = accPoK.offset = cursor;
        accPoK.length = payload.length;

        accPoK.parse();

        if (accPoK.length == UNKNOWN_LENGTH) {
            Preconditions.checkState(false, "Length field has not been set in constructor for %s after parse.", accPoK.getClass().getSimpleName());
        }

        if (retainMode) {
            accPoK.payload = null;
        }
        return accPoK;
    }


    @Override
    protected void parse() throws ProtocolException {
        C_e = readBignum();
        C_u = readBignum();
        C_r = readBignum();
        st_1 = readBignum();
        st_2 = readBignum();
        st_3 = readBignum();
        t_1 = readBignum();
        t_2 = readBignum();
        t_3 = readBignum();
        t_4 = readBignum();
        s_alpha = readBignum();
        s_beta = readBignum();
        s_zeta = readBignum();
        s_sigma = readBignum();
        s_eta = readBignum();
        s_epsilon = readBignum();
        s_delta = readBignum();
        s_xi = readBignum();
        s_phi = readBignum();
        s_gamma = readBignum();
        s_psi = readBignum();
    }

    @Override
    public byte[] bitcoinSerialize() {
        ByteArrayOutputStream buffer = null;
        try {
            buffer = new ByteArrayOutputStream();
            ZUtils.serializeBigInteger(buffer,C_e);
            ZUtils.serializeBigInteger(buffer,C_u);
            ZUtils.serializeBigInteger(buffer,C_r);
            ZUtils.serializeBigInteger(buffer,st_1);
            ZUtils.serializeBigInteger(buffer,st_2);
            ZUtils.serializeBigInteger(buffer,st_3);
            ZUtils.serializeBigInteger(buffer,t_1);
            ZUtils.serializeBigInteger(buffer,t_2);
            ZUtils.serializeBigInteger(buffer,t_3);
            ZUtils.serializeBigInteger(buffer,t_4);
            ZUtils.serializeBigInteger(buffer,s_alpha);
            ZUtils.serializeBigInteger(buffer,s_beta);
            ZUtils.serializeBigInteger(buffer,s_zeta);
            ZUtils.serializeBigInteger(buffer,s_sigma);
            ZUtils.serializeBigInteger(buffer,s_eta);
            ZUtils.serializeBigInteger(buffer,s_epsilon);
            ZUtils.serializeBigInteger(buffer,s_delta);
            ZUtils.serializeBigInteger(buffer,s_xi);
            ZUtils.serializeBigInteger(buffer,s_phi);
            ZUtils.serializeBigInteger(buffer,s_gamma);
            ZUtils.serializeBigInteger(buffer,s_psi);
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize accPoK ", e);
        } finally {
            if (buffer != null) {
                try {
                    buffer.close();
                } catch (IOException e) {
                    // nothing
                }
            }
        }
    }

    public int getCursor() {
        return this.cursor;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AccumulatorProofOfKnowledge that = (AccumulatorProofOfKnowledge) o;
        return ZUtils.equals(C_e, that.C_e) &&
                ZUtils.equals(C_u, that.C_u) &&
                ZUtils.equals(C_r, that.C_r) &&
                ZUtils.equals(st_1, that.st_1) &&
                ZUtils.equals(st_2, that.st_2) &&
                ZUtils.equals(st_3, that.st_3) &&
                ZUtils.equals(t_1, that.t_1) &&
                ZUtils.equals(t_2, that.t_2) &&
                ZUtils.equals(t_3, that.t_3) &&
                ZUtils.equals(t_4, that.t_4) &&
                ZUtils.equals(s_alpha, that.s_alpha) &&
                ZUtils.equals(s_beta, that.s_beta) &&
                ZUtils.equals(s_zeta, that.s_zeta) &&
                ZUtils.equals(s_sigma, that.s_sigma) &&
                ZUtils.equals(s_eta, that.s_eta) &&
                ZUtils.equals(s_epsilon, that.s_epsilon) &&
                ZUtils.equals(s_delta, that.s_delta) &&
                ZUtils.equals(s_xi, that.s_xi) &&
                ZUtils.equals(s_phi, that.s_phi) &&
                ZUtils.equals(s_gamma, that.s_gamma) &&
                ZUtils.equals(s_psi, that.s_psi);
    }

    @Override
    public int hashCode() {
        return Objects.hash(zParams, C_e, C_u, C_r, st_1, st_2, st_3, t_1, t_2, t_3, t_4, s_alpha, s_beta, s_zeta, s_sigma, s_eta, s_epsilon, s_delta, s_xi, s_phi, s_gamma, s_psi);
    }

    @Override
    public String toString() {
        return "AccumulatorProofOfKnowledge{" +
                "zParams=" + zParams +
                ",\n C_e=" + C_e +
                ",\n C_u=" + C_u +
                ",\n C_r=" + C_r +
                ",\n st_1=" + st_1 +
                ",\n st_2=" + st_2 +
                ",\n st_3=" + st_3 +
                ",\n t_1=" + t_1 +
                ",\n t_2=" + t_2 +
                ",\n t_3=" + t_3 +
                ",\n t_4=" + t_4 +
                ",\n s_alpha=" + s_alpha +
                ",\n s_beta=" + s_beta +
                ",\n s_zeta=" + s_zeta +
                ",\n s_sigma=" + s_sigma +
                ",\n s_eta=" + s_eta +
                ",\n s_epsilon=" + s_epsilon +
                ",\n s_delta=" + s_delta +
                ",\n s_xi=" + s_xi +
                ",\n s_phi=" + s_phi +
                ",\n s_gamma=" + s_gamma +
                ",\n s_psi=" + s_psi +
                '}';
    }
}
