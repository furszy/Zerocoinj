// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core;

import com.zerocoinj.core.context.ZerocoinContext;
import com.zerocoinj.core.exceptions.InvalidSerialException;
import com.zerocoinj.utils.ZUtils;
import org.json.JSONObject;
import org.pivxj.core.DumpedPrivateKey;
import org.pivxj.core.ECKey;
import org.pivxj.core.NetworkParameters;
import org.pivxj.core.Sha256Hash;
import org.pivxj.params.MainNetParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.BigIntegers;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Objects;

import static com.zerocoinj.core.context.ZerocoinDefines.MAX_COINMINT_ATTEMPTS;
import static com.zerocoinj.core.context.ZerocoinDefines.ZEROCOIN_MINT_PRIME_PARAM;

public class ZeroCoin {

    private static final Logger logger = LoggerFactory.getLogger(ZeroCoin.class);

    public static int PUBKEY_VERSION = 2;
    public static int CURRENT_VERSION = 2;
    public static int V2_BITSHIFT = 4;

    // Context
    private final ZerocoinContext params;
    // Mint data
    private int version = 2;
    private Commitment commitment;
    private BigInteger serial;
    private CoinDenomination coinDenomination;
    private ECKey keyPair;
    // Blockchain data
    private Sha256Hash parentTxId;
    private int height;

    public ZeroCoin(ZerocoinContext params, BigInteger serial, Commitment commitment, CoinDenomination coinDenomination, ECKey keyPair) {
        this.params = params;
        this.commitment = commitment;
        this.serial = serial;
        this.coinDenomination = coinDenomination;
        this.keyPair = keyPair;
    }

    public int getVersion() {
        return version;
    }

    public Commitment getCommitment() {
        return commitment;
    }

    public BigInteger getSerial() {
        return serial;
    }

    public CoinDenomination getCoinDenomination() {
        return coinDenomination;
    }

    public ECKey getKeyPair() {
        return keyPair;
    }

    public Sha256Hash getParentTxId() {
        return parentTxId;
    }

    public int getHeight() {
        return height;
    }

    public void setParentTxId(Sha256Hash parentTxId) {
        this.parentTxId = parentTxId;
    }

    public void setHeight(int height) {
        this.height = height;
    }

    public void setCoinDenomination(CoinDenomination coinDenomination) {
        if (this.coinDenomination != CoinDenomination.ZQ_ERROR) throw new IllegalStateException("Coin already has a valid denomination");
        this.coinDenomination = coinDenomination;
    }

    public void setKeyPair(ECKey keyPair) {
        this.keyPair = keyPair;
    }

    public boolean validate() {
        BigInteger commitmentValue = getCommitment().getCommitmentValue();
        if (params.getAccumulatorParams().getMinCoinValue().compareTo(commitmentValue) >= 1) {
            logger.info( "zeroCoin validate value is too low: " + getCommitment().getCommitmentValue().toString());
            return false;
        }

        if (commitmentValue.compareTo(params.getAccumulatorParams().getMaxCoinValue()) > 0) {
            logger.info("PublicCoin::validate value is too high, value: " + getCommitment().getCommitmentValue());
            return false;
        }

        if (!commitmentValue.isProbablePrime(params.getZkp_iterations())) {
            logger.info("zeroCoin validate, value is not prime. value " + commitmentValue.toString());
            return false;
        }

        return true;
    }

    // Check if the value of the commitment meets requirements
    public static boolean isCoinValueValid(ZerocoinContext context, BigInteger bnValue) {
        return ZUtils.isGreaterOrEqualThan(bnValue , context.accumulatorParams.getMinCoinValue()) &&
            ZUtils.isLessOrEqualThan(bnValue , context.accumulatorParams.getMaxCoinValue()) &&
            bnValue.isProbablePrime(context.getZkp_iterations());
    }


    public static ZeroCoin mintCoin(ZerocoinContext zerocoinContext, ECKey key, CoinDenomination coinDenomination) throws InvalidSerialException {
        BigInteger serial = generateSerial(key);
        Commitment commitment = generateCommitment(zerocoinContext, serial);
        return new ZeroCoin(zerocoinContext, serial, commitment, coinDenomination, key);
    }

    public static ZeroCoin mintCoinH(ZerocoinContext zerocoinContext, ECKey key, CoinDenomination coinDenomination, Commitment commitment) throws InvalidSerialException {
        BigInteger serial = generateSerial(key);
        if (!ZUtils.equals(serial, commitment.getContent())) throw new IllegalStateException("Invalid commitment serial");
        return new ZeroCoin(zerocoinContext, serial, commitment, coinDenomination, key);
    }

    public static ZeroCoin mintCoinUnchecked(ZerocoinContext zerocoinContext, ECKey key, CoinDenomination coinDenomination, Commitment commitment) {
        return new ZeroCoin(zerocoinContext, commitment.getContent(), commitment, coinDenomination, key);
    }

    public static BigInteger generateSerial(ECKey pubKey) throws InvalidSerialException{
        return generateSerial(pubKey.getPubKey());
    }

    public static BigInteger generateSerial(byte[] pubKey) throws InvalidSerialException {
        // Generate a new serial, which also has a 256-bit pubkey hash that qualifies as a serial #
        byte[] pubKeyHash = Sha256Hash.twiceOf(pubKey).getReversedBytes();
        return generateSerialFrom(pubKeyHash);
    }

    public static BigInteger generateSerialFrom(byte[] data) throws InvalidSerialException {
        byte[] pubKeyHash = data;
        BigInteger hashNum = new BigInteger(1, pubKeyHash);
        if (hashNum.signum() == -1){
            byte[] hashNum2 = Uint256.parseBigIntegerPositive(hashNum);
            hashNum = new BigInteger(1, hashNum2);
        }

        // Check if this is 256 bits
        //if (hashNum.bitLength() != 255) throw new InvalidSerialException(String.format("PubKey hash is not 256 bits length : %d",hashNum.bitLength()));

        // Make the first half byte 0 which will distinctly mark v2 serials
        hashNum = hashNum.shiftRight(V2_BITSHIFT);

        BigInteger nBits = hashNum.shiftRight(248); // must be less than 0x0D to be valid serial range

        if (nBits.intValue() > 12) {
            logger.warn("generateSerial fail, must be less than 0x0d to be a valid serial range");
            throw new InvalidSerialException("Serial generation fail, nBits must be less than 0x0d to be a valid serial range");
        }

        //Mark this as v2 by starting with 0xF
        BigInteger nMark = new BigInteger("F",16);
        nMark = nMark.shiftLeft(252);
        hashNum = hashNum.or(nMark);

        if (ZeroCoin.extractVersionFromSerial(hashNum) != CURRENT_VERSION){
            throw new InvalidSerialException("Invalid version ,zeroCoin created with an invalid serial --> " + Hex.toHexString(hashNum.toByteArray()));
        }

        // Quick workaround to cleanup the first 2 zeros.
        return hashNum;
    }

    /**
     *  Remove the first four bits for V2 serials
     */
    public static BigInteger getAdjustedSerial(BigInteger bnSerial){
        byte[] bytes = new byte[32];
        bytes[0] = 0xf;
        BigInteger value = new BigInteger(bytes).shiftLeft(V2_BITSHIFT);
        bnSerial = bnSerial.andNot(value);
        return bnSerial;
    }

    public static Commitment generateCommitment(ZerocoinContext context, BigInteger serial, BigInteger randomness){
        Commitment commitment = new Commitment(serial, randomness, context.getCoinCommitmentGroup());
        return generateCommitment(context,commitment);
    }
    public static Commitment generateCommitment(ZerocoinContext context, BigInteger serial){
        Commitment commitment = new Commitment(serial, context.getCoinCommitmentGroup());
        return generateCommitment(context, commitment);
    }

    public static Commitment generateCommitment(ZerocoinContext context, Commitment commitment){
        BigInteger commitmentValue = commitment.getCommitmentValue();
        BigInteger r = commitment.getRandomness();
        // Repeat this process up to MAX_COINMINT_ATTEMPTS times until
        // we obtain a prime number
        for (int attempt = 0; attempt < MAX_COINMINT_ATTEMPTS; attempt++) {
            // First verify that the commitment is a prime number
            // in the appropriate range. If not, we'll throw this coin
            // away and generate a new one.

            if (commitmentValue.isProbablePrime(ZEROCOIN_MINT_PRIME_PARAM) &&
                    commitmentValue.compareTo(context.getAccumulatorParams().getMinCoinValue()) >= 1 &&
                    commitmentValue.compareTo(context.getAccumulatorParams().getMaxCoinValue()) <= -1) {

                // Found a valid coin. Store it.
                //logger.info("Commitment value found: " + commitmentValue.toString());
                return new Commitment(commitment.getContent(), commitmentValue, r);
            }

            // Generate a new random "r_delta" in 0...{q-1}
            BigInteger r_delta = BigIntegers.createRandomInRange(BigInteger.ZERO, context.getCoinCommitmentGroup().getGroupOrder(), ZerocoinContext.getSecureRandom());

            // The commitment was not prime. Increment "r" and recalculate "C":
            // r = r + r_delta mod q
            // C = C * h mod p
            r = r.add(r_delta).mod(context.getCoinCommitmentGroup().getGroupOrder());
            commitmentValue =
                    commitmentValue.multiply(
                            context.getCoinCommitmentGroup().getH().modPow(r_delta, context.getCoinCommitmentGroup().getModulus())
                    ).mod(context.getCoinCommitmentGroup().getModulus());
        }

        // We only get here if we did not find a coin within
        // MAX_COINMINT_ATTEMPTS. Throw an exception.
        throw new RuntimeException("Unable to create a new valid commitment (too many attempts)");
    }

    public static int extractVersionFromSerial(BigInteger bnSerial) {
        BigInteger base = BigInteger.valueOf(0xf);
        BigInteger moved = bnSerial.shiftRight(252);
        //Serial is marked as v2 only if the first byte is 0xF
        BigInteger nMark = bnSerial.shiftRight(256 - V2_BITSHIFT).and(base);
        BigInteger v2Mark = BigInteger.valueOf(0xf);
        if (nMark.compareTo(v2Mark) == 0)
            return PUBKEY_VERSION;
        return 1;
    }


    /**
     * Check if the public part of this coins is the same.
     * // TODO: Check that the params for both coins are equals.. i'm not doing now basically because there is just one possible param
     * @param obj
     * @return
     */
    public boolean publicEquals(ZeroCoin obj) {
        return
                ZUtils.equals(this.commitment.getCommitmentValue(), obj.commitment.getCommitmentValue()) &&
                          this.coinDenomination == obj.coinDenomination;
    }

    @Override
    public String toString() {
        return "zeroCoin{" +toJsonString() +'}';
    }

    // Json keys
    public static final String DENOMINATION = "d";
    public static final String COMMITMENT_VALUE = "p";
    public static final String MINTED_HEIGHT = "h";
    public static final String SERIAL_VERSION = "v";
    public static final String SERIAL = "s";
    public static final String COMMITMENT_RANDOMNESS = "r";
    public static final String MINT_TX = "t";
    public static final String IS_COIN_USED = "u";
    public static final String PRIV_KEY = "k";


    public static ZeroCoin fromJson(NetworkParameters params, ZerocoinContext zerocoinContext, String jsonStr){
        JSONObject jsonObject = new JSONObject(jsonStr);
        BigInteger commitmentValue = new BigInteger(jsonObject.getString(COMMITMENT_VALUE),16);
        BigInteger serial = new BigInteger(jsonObject.getString(SERIAL),16);
        BigInteger randomness = new BigInteger(jsonObject.getString(COMMITMENT_RANDOMNESS),16);

        //ECKey ecKey = ECKey.fromPrivate(Hex.decode(jsonObject.getString(PRIV_KEY)));
        ZeroCoin zeroCoin = new ZeroCoin(
                zerocoinContext,
                serial,
                new Commitment(serial, commitmentValue, randomness),
                CoinDenomination.fromValue(jsonObject.getInt(DENOMINATION)),
                DumpedPrivateKey.fromBase58(params, jsonObject.getString(PRIV_KEY)).getKey()
        );
        zeroCoin.setHeight(jsonObject.getInt(MINTED_HEIGHT));
        zeroCoin.setParentTxId(Sha256Hash.wrap(jsonObject.getString(MINT_TX)));
        zeroCoin.version = jsonObject.getInt(SERIAL_VERSION);
        return zeroCoin;
    }

    /**
     * TODO: Change the "u":false (means used in the core method 'importzerocoins')
     * @return
     */
    public String toJsonString(){
        /**
         * ﻿'[{"d":100,"p":"mypubcoin","s":"myserial","r":"randomness_hex","t":"mytxid","h":104923, "u":false},{"d":5,...}]'﻿'[{"d":100,"p":"mypubcoin","s":"myserial","r":"randomness_hex","t":"mytxid","h":104923, "u":false},{"d":5,...}]'
         */
        return "{" +
                "\"d\":" + coinDenomination.getDenomination() +
                ",\"p\":\"" + commitment.getCommitmentValue().toString(16) +
                "\",\"h\":" + height +
                ",\"v\":" + version +
                ",\"s\":\"" + serial.toString(16) +
                "\",\"r\":\"" + commitment.getRandomness().toString(16) +
                "\",\"t\":\"" + ( (parentTxId != null) ? Hex.toHexString(parentTxId.getReversedBytes()) : "null" ) +
                "\",\"u\":" + "false" +
                ",\"k\":\"" + keyPair.getPrivateKeyEncoded(MainNetParams.get()) +
                "\"}";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZeroCoin zeroCoin = (ZeroCoin) o;
        return version == zeroCoin.version &&
                commitment.equals(zeroCoin.commitment) &&
                ZUtils.equals(serial, zeroCoin.serial) &&
                coinDenomination == zeroCoin.coinDenomination &&
                keyPair.equals(zeroCoin.keyPair);
    }

    @Override
    public int hashCode() {

        return Objects.hash(version, commitment, serial, coinDenomination, keyPair);
    }
}
