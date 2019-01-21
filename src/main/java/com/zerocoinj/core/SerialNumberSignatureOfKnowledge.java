// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core;

import com.google.common.base.Preconditions;
import com.zerocoinj.core.context.ZerocoinContext;
import com.zerocoinj.utils.ZUtils;
import org.pivxj.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import static com.zerocoinj.utils.ZUtils.random;

/**
 * A Signature of knowledge on the hash of metadata attesting that the signer knows the values
 *  necessary to open a commitment which contains a coin(which it self is of course a commitment)
 * with a given serial number.
 */
public class SerialNumberSignatureOfKnowledge extends Message {

    private static final Logger log = LoggerFactory.getLogger(SerialNumberSignatureOfKnowledge.class);

    private ZerocoinContext zParams;
    // Challenge hash
    private Sha256Hash hash;

    // challenge response values
    // this is s_notprime instead of s
    // because the serialization macros
    // define something named s and it conflicts
    private BigInteger[] s_notprime;
    private BigInteger[] sprime;

    public static SerialNumberSignatureOfKnowledge parse(NetworkParameters params, ZerocoinContext zParams, byte[] payload, int cursor, boolean retainMode) {
        SerialNumberSignatureOfKnowledge sok = new SerialNumberSignatureOfKnowledge(params);
        // Add protocol if i need it in the future
        //sok.protocolVersion = protocolVersion;
        sok.zParams = zParams;
        sok.payload = payload;
        sok.cursor = sok.offset = cursor;
        sok.length = payload.length;

        sok.parse();

        if (sok.length == UNKNOWN_LENGTH) {
            Preconditions.checkState(false, "Length field has not been set in constructor for %s after parse.", sok.getClass().getSimpleName());
        }

        if (retainMode) {
            sok.payload = null;
        }
        return sok;
    }

    public SerialNumberSignatureOfKnowledge(NetworkParameters params) {
        super(params);
    }

    /**
     * Creates a Signature of knowledge object that a commitment to a coin contains a coin with serial number x
     *
     * @param p params
     * @param coin the coin we are going to prove the serial number of.
     * @param commitmentToCoin the commitment to the coin
     * @param msghash hash of meta data to create a signature of knowledge on.
     */
    public SerialNumberSignatureOfKnowledge(ZerocoinContext p, final ZeroCoin coin, final Commitment commitmentToCoin, Sha256Hash msghash, RandomNumbers randomNumbers){
        this.zParams = p;
        this.s_notprime = new BigInteger[p.getZkp_iterations()];
        this.sprime = new BigInteger[p.getZkp_iterations()];

        // Sanity check: verify that the order of the "accumulatedValueCommitmentGroup" is
        // equal to the modulus of "coinCommitmentGroup". Otherwise we will produce invalid
        // proofs.
        if (! ZUtils.equals( zParams.getCoinCommitmentGroup().getModulus() , zParams.getSerialNumberSoKCommitmentGroup().getGroupOrder() )) {
            throw new RuntimeException("Groups are not structured correctly.");
        }

        BigInteger a = zParams.getCoinCommitmentGroup().getG();
        BigInteger b = zParams.getCoinCommitmentGroup().getH();
        BigInteger g = zParams.getSerialNumberSoKCommitmentGroup().getG();
        BigInteger h = zParams.getSerialNumberSoKCommitmentGroup().getH();

        HashWriter hasher = new HashWriter();
        hasher.write(zParams)
                .write(commitmentToCoin.getCommitmentValue())
                .write(coin.getSerial())
                .write(msghash);

        BigInteger[] r = new BigInteger[p.getZkp_iterations()];
        BigInteger[] v_seed = new BigInteger[p.getZkp_iterations()];
        BigInteger[] v_expanded = new BigInteger[p.getZkp_iterations()];
        BigInteger[] c = new BigInteger[p.getZkp_iterations()];

        if (randomNumbers != null){
            // Load random numbers from c++ code to check if this is what is falling
            // which is 96% probable..
            r = randomNumbers.r;
            v_seed = randomNumbers.v_seed;
            v_expanded = randomNumbers.v_expanded;
        }else {

            for (int i = 0; i < zParams.getZkp_iterations(); i++) {
                r[i] = random(zParams.getCoinCommitmentGroup().getGroupOrder());

                //use a random 256 bit seed that expands to 1024 bit for v[i]
                //BigInteger notZero256Bits = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639935");
                while (true) {
                /*BigInteger randomBignum = random(notZero256Bits);
                // TODO: this toUint256 method is not right for negative numbers..
                byte[] random = HashWriter.toUint2562(randomBignum,false);
                BigInteger bnExpanded =
                        Utils.decodeMPI(
                                Utils.reverseBytes(
                                        jniBridge.compute1024seed(random)
                                ),
                                false
                                );*/

                    String ret = zParams.jniBridge.computeVSeedAndVExpanded();
                    String[] retStr = ret.split("\\|\\|");
                    BigInteger vSeed = new BigInteger(retStr[0]);
                    BigInteger bnExpanded = new BigInteger(retStr[1]);

                    if (ZUtils.isGreaterThan(bnExpanded, zParams.getSerialNumberSoKCommitmentGroup().getGroupOrder()))
                        continue;

                    //BigInteger v_seedI = Utils.decodeMPI(random, false);
                    // v_seed could be different that 32 bytes here
                    //if (random.length != 32){
                    //    log.info("invalid v_seed, size is not 32 bytes, : " + random);
                    //    continue;
                    //}
                    v_seed[i] = vSeed; //Utils.decodeMPI(random,false);
                    v_expanded[i] = bnExpanded;
                    break;
                }
            }
        }

        for(int i=0; i < zParams.getZkp_iterations(); i++) {
            // compute g^{ {a^x b^r} h^v} mod p2
            c[i] = challengeCalculation(coin.getSerial(), r[i], v_expanded[i]);
        }

        // We can't hash data in parallel either
        // because OPENMP cannot not guarantee loops
        // execute in order.
        for(int i=0; i < zParams.getZkp_iterations(); i++) {
            hasher.write(c[i]);
        }

        byte[] hashbytes = hasher.doubleShaReversed();
        this.hash = Sha256Hash.wrap(hashbytes);
        hashbytes = this.hash.getReversedBytes();

        for(int i = 0; i < zParams.getZkp_iterations(); i++) {
            int bit = i % 8;
            int sByte = i / 8;

            boolean challenge_bit = ((hashbytes[sByte] >> bit) & 0x01) == 1; // true if the value is 1
            if (challenge_bit) {
                s_notprime[i]       = r[i];
                sprime[i]           = v_seed[i];
            } else {
                s_notprime[i]       = r[i] .subtract( coin.getCommitment().getRandomness() );
                sprime[i]           = v_expanded[i] .subtract (commitmentToCoin.getRandomness() .multiply(
                        b.modPow(r[i] .subtract( coin.getCommitment().getRandomness() ), zParams.getSerialNumberSoKCommitmentGroup().getGroupOrder()))
                        );
            }
        }
    }


    public static class RandomNumbers{

        public BigInteger[] r;
        public BigInteger[] v_seed;
        public BigInteger[] v_expanded;

        public RandomNumbers() {
            r = new BigInteger[80];
            v_seed = new BigInteger[80];
            v_expanded = new BigInteger[80];
        }
    }


    private BigInteger challengeCalculation(final BigInteger a_exp,final BigInteger b_exp,
        final BigInteger h_exp) {

        BigInteger a = zParams.getCoinCommitmentGroup().getG();
        BigInteger b = zParams.getCoinCommitmentGroup().getH();
        BigInteger g = zParams.getSerialNumberSoKCommitmentGroup().getG();
        BigInteger h = zParams.getSerialNumberSoKCommitmentGroup().getH();

        BigInteger exponent = (a.modPow(a_exp, zParams.getSerialNumberSoKCommitmentGroup().getGroupOrder())
                            .multiply(b.modPow(b_exp, zParams.getSerialNumberSoKCommitmentGroup().getGroupOrder())
                            ) ) .mod(zParams.getSerialNumberSoKCommitmentGroup().getGroupOrder());

        return (g.modPow(exponent, zParams.getSerialNumberSoKCommitmentGroup().getModulus()) .multiply( h.modPow(h_exp, zParams.getSerialNumberSoKCommitmentGroup().getModulus()))
            ).mod( zParams.getSerialNumberSoKCommitmentGroup().getModulus());
    }

    // Use one 256 bit seed and concatenate 4 unique 256 bit hashes to make a 1024 bit hash
    public static BigInteger SeedTo1024(byte[] hashSeed) {
        int size = 32;
        byte[] byteBuffer = new byte[size];
        HashWriter hasher = new HashWriter();

        hasher.writeInternal(hashSeed);

        for (int i = 0; i < 4; i++) {
            BigInteger hashedBignum = hasher.toUint256(null,false);
            byte[] vHash = Utils.reverseBytes(Utils.encodeMPI(hashedBignum, false));
            System.arraycopy(vHash, 0, byteBuffer, size * i, vHash.length);

            // TODO: Check if this is good, pretty sure that we need to
            hasher.writeInternal(new VarInt(byteBuffer.length).encode());
            hasher.writeInternal(byteBuffer);

            byte[] temp = new byte[byteBuffer.length + 32];
            System.arraycopy(byteBuffer, 0, temp, 0, byteBuffer.length);
            byteBuffer = temp;
        }
        return Utils.decodeMPI(byteBuffer, false);
    }

    public boolean verify(final BigInteger coinSerialNumber, BigInteger valueOfCommitmentToCoin, Sha256Hash msghash) {
        BigInteger a = zParams.getCoinCommitmentGroup().getG();
        BigInteger b = zParams.getCoinCommitmentGroup().getH();
        BigInteger g = zParams.getSerialNumberSoKCommitmentGroup().getG();
        BigInteger h = zParams.getSerialNumberSoKCommitmentGroup().getH();
        HashWriter hasher = new HashWriter();
        hasher.write(zParams)
                .write(valueOfCommitmentToCoin)
                .write(coinSerialNumber)
                .write(msghash);

        BigInteger[] tprime = new BigInteger[zParams.getZkp_iterations()];

        byte[] hashbytes = this.hash.getReversedBytes();

        //log.info("Hash bytes: " + Hex.toHexString(hashbytes));

        for(int i = 0; i < zParams.getZkp_iterations(); i++) {
            try {
                int bit = i % 8;
                int sByte = i / 8;
                boolean challenge_bit = ((hashbytes[sByte] >> bit) & 0x01) == 1; // true if the value is 1 (todo: check me..)
                if (challenge_bit) {
                    byte[] res = zParams.jniBridge.compute1024seed(Utils.reverseBytes(Utils.encodeMPI(sprime[i], false)));
                    BigInteger result = Utils.decodeMPI(Utils.reverseBytes(res), false);
                    tprime[i] = challengeCalculation(
                            coinSerialNumber,
                            s_notprime[i],
                            result
                            //SeedTo1024(
                            //        Utils.reverseBytes(
                            //                Utils.encodeMPI(sprime[i], false)
                            //        )
                            //)
                    );
                    //log.info("(challenge bit true) tprime pos: " + i + " , number in DEC: " + tprime[i] +",\n compute1024Seed DEC: " + result+"\n");
                } else {
                    BigInteger exp = b.modPow(s_notprime[i], zParams.getSerialNumberSoKCommitmentGroup().getGroupOrder());
                    tprime[i] = (
                            (valueOfCommitmentToCoin.modPow(exp, zParams.getSerialNumberSoKCommitmentGroup().getModulus()).mod(zParams.getSerialNumberSoKCommitmentGroup().getModulus())).multiply(
                                    (h.modPow(sprime[i], zParams.getSerialNumberSoKCommitmentGroup().getModulus()).mod(zParams.getSerialNumberSoKCommitmentGroup().getModulus()))
                            )).mod(zParams.getSerialNumberSoKCommitmentGroup().getModulus());
                    //log.info("(challenge bit false) tprime pos: " + i + " , number in DEC: " + tprime[i] +"\n");
                }
            }catch (Exception e){
                e.printStackTrace();
                BigInteger bn = sprime[i];
                log.debug("Error in bn: " + bn);
                byte[] bnArray = Utils.encodeMPI(sprime[i], true);
                log.debug("Bn size: "+ bnArray.length +", encoded: " + Hex.toHexString(bnArray));
                throw new RuntimeException(e);
            }
        }
        for(int i = 0; i < zParams.getZkp_iterations(); i++) {
            hasher.write(tprime[i]);
        }
        return Sha256Hash.wrap(hasher.doubleShaReversed()).equals(hash);
    }


    @Override
    protected void parse() throws ProtocolException {
        long amountOfSNotPrime = readVarInt();
        this.s_notprime = new BigInteger[(int) amountOfSNotPrime];
        for (int i = 0; i < amountOfSNotPrime; i++) {
            this.s_notprime[i] = readBignum();
        }
        long amountOfsPrime = readVarInt();
        this.sprime = new BigInteger[(int) amountOfsPrime];
        for (int i = 0; i < amountOfsPrime; i++) {
            this.sprime[i] = readBignum();
        }
        this.hash = readHash();
    }

    @Override
    public byte[] unsafeBitcoinSerialize() {
        ByteArrayOutputStream buffer = null;
        try {
            buffer = new ByteArrayOutputStream();
            serialize(buffer, s_notprime);
            serialize(buffer, sprime);
            buffer.write(hash.getReversedBytes());
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize SerialNumberSoK", e);
        } finally {
            try {
                if (buffer != null) {
                    buffer.close();
                }
            } catch (IOException e) {
                // Nothing..
            }
        }
    }

    private void serialize(ByteArrayOutputStream buf, BigInteger[] nums) throws IOException {
        buf.write(new VarInt(nums.length).encode());
        for (BigInteger bigInteger : nums) {
            byte[] num = ZUtils.serializeBigInteger(bigInteger);
            buf.write(new VarInt(num.length).encode());
            buf.write(num);
        }
    }

     /**
     * TODO: Implement this if it's needed..
     * @param stream
     */
    public void serialize(FStream stream){
        /**
         * READWRITE(s_notprime);
         * READWRITE(sprime);
         * READWRITE(hash);
         */
    }

    public int getCursor() {
        return this.cursor;
    }
}
