// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core;

import com.google.common.base.Preconditions;
import com.zerocoinj.core.accumulators.Accumulator;
import com.zerocoinj.core.accumulators.AccumulatorProofOfKnowledge;
import com.zerocoinj.core.accumulators.AccumulatorWitness;
import com.zerocoinj.core.context.ZerocoinContext;
import com.zerocoinj.utils.ZUtils;
import org.pivxj.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

import static com.zerocoinj.core.ZeroCoin.*;
import static com.zerocoinj.utils.ZUtils.serializeBytesVarInt;

/**
 * The complete proof needed to spend a zerocoin.
 * Composes together a proof that a coin is accumulated
 * and that it has a given serial number.
 */
public class CoinSpend extends Message {

    private Logger log = LoggerFactory.getLogger(CoinSpend.class);

    private ZerocoinContext zParams;

    private CoinDenomination denomination;
    // uint32
    private BigInteger accChecksum;
    // Transaction in which this spend is broadcasted (just the outputs).
    private Sha256Hash pTxHash;
    private BigInteger accCommitmentToCoinValue;
    private BigInteger serialCommitmentToCoinValue;
    private BigInteger coinSerialNumber;
    private AccumulatorProofOfKnowledge accumulatorPoK;
    private SerialNumberSignatureOfKnowledge serialNumberSoK;
    private CommitmentProofOfKnowledge commitmentPoK;
    private int version;

    // Version 2
    private ECKey pubKey;
    private byte[] vchSig;
    private SpendType spendType;

    public static CoinSpend parse(NetworkParameters params, ZerocoinContext zParams, byte[] payload){
        CoinSpend coinSpend = new CoinSpend(params);
        // Add protocol if i need it in the future
        //sok.protocolVersion = protocolVersion;
        coinSpend.zParams = zParams;
        coinSpend.payload = payload;
        coinSpend.cursor = coinSpend.offset = 0;
        coinSpend.length = payload.length;

        coinSpend.parse();

        if (coinSpend.length == UNKNOWN_LENGTH) {
            Preconditions.checkState(false, "Length field has not been set in constructor for %s after parse.", coinSpend.getClass().getSimpleName());
        }

        if (!coinSpend.serializer.isParseRetainMode()) {
            coinSpend.payload = null;
        }
        return coinSpend;
    }

    private CoinSpend(NetworkParameters params) {
        super(params);
    }

    /**
     * Generates a proof spending a zerocoin.
     *
     * To use this, provide an unspent PrivateCoin, the latest Accumulator
     * (e.g from the most recent Bitcoin block) containing the public part
     * of the coin, a witness to that, and whatever medeta data is needed.
     *
     * Once constructed, this proof can be serialized and sent.
     * It is validated simply be calling validate.
     * @warning Validation only checks that the proof is correct
     * @warning for the specified values in this class. These values must be validated
     *  Clients ought to check that
     * 1) params is the right params
     * 2) the accumulator actually is in some block
     * 3) that the serial number is unspent
     * 4) that the transaction
     *
     * @param params cryptographic parameters
     * @param coin The coin to be spend
     * @param a The current accumulator containing the coin
     * @param witness The witness showing that the accumulator contains the coin
     * @param a hash of the partial transaction that contains this coin spend
     * @throw ZerocoinException if the process fails
     */
    public CoinSpend(final ZerocoinContext params, final ZeroCoin coin, Accumulator a, final BigInteger checksum,
                     final AccumulatorWitness witness, final Sha256Hash pTxHash, final SpendType spendType,
                     SerialNumberSignatureOfKnowledge.RandomNumbers randomNumbers
    ){

        this.denomination = coin.getCoinDenomination();
        this.version = coin.getVersion();
        this.pTxHash = pTxHash;
        this.coinSerialNumber = coin.getSerial();
        this.spendType = spendType;
        this.accChecksum = checksum;

        // Sanity check: let's verify that the Witness is valid with respect to
        // the coin and Accumulator provided.
        if (!(witness.verifyWitness(a, coin))) {
            //std::cout << "CoinSpend: Accumulator witness does not verify\n";
            throw new RuntimeException("Accumulator witness does not verify");
        }

        // 1: Generate two separate commitments to the public coin (C), each under
        // a different set of public parameters. We do this because the RSA accumulator
        // has specific requirements for the commitment parameters that are not
        // compatible with the group we use for the serial number proof.
        // Specifically, our serial number proof requires the order of the commitment group
        // to be the same as the modulus of the upper group. The Accumulator proof requires a
        // group with a significantly larger order.

        final Commitment fullCommitmentToCoinUnderSerialParams =
                new Commitment(
                        coin.getCommitment().getCommitmentValue(),
                        params.getSerialNumberSoKCommitmentGroup()
                );

        this.serialCommitmentToCoinValue = fullCommitmentToCoinUnderSerialParams.getCommitmentValue();

        final Commitment fullCommitmentToCoinUnderAccParams =
                new Commitment(
                        coin.getCommitment().getCommitmentValue(),
                        params.getAccumulatorParams().getAccumulatorPoKCommitmentGroup()
                );

        this.accCommitmentToCoinValue = fullCommitmentToCoinUnderAccParams.getCommitmentValue();

        // 2. Generate a ZK proof that the two commitments contain the same public coin.
        this.commitmentPoK = new CommitmentProofOfKnowledge(
                params.getSerialNumberSoKCommitmentGroup(),
                params.getAccumulatorParams().getAccumulatorPoKCommitmentGroup(),
                fullCommitmentToCoinUnderSerialParams,
                fullCommitmentToCoinUnderAccParams
        );

        if(!this.commitmentPoK.verify(serialCommitmentToCoinValue, accCommitmentToCoinValue)){
            throw new RuntimeException("commitmentPoK failed");
        }
        //log.info("CommitmentPoK OK! \n" + commitmentPoK);

        // Now generate the two core ZK proofs:
        // 3. Proves that the committed public coin is in the Accumulator (PoK of "witness")
        this.accumulatorPoK = new AccumulatorProofOfKnowledge(
                params.getAccumulatorParams(),
                fullCommitmentToCoinUnderAccParams,
                witness,
                a
        );

        if(! this.accumulatorPoK.verify(a, fullCommitmentToCoinUnderAccParams.getCommitmentValue())){
            throw new RuntimeException("AccumulatorPoK invalid");
        }
        //log.info("Accumulator PoK ok! \n " + this.accumulatorPoK);

        // 4. Proves that the coin is correct w.r.t. serial number and hidden coin secret
        // (This proof is bound to the coin 'metadata', i.e., transaction hash)
        Sha256Hash hashSig = Sha256Hash.wrap(signatureHash());
        this.serialNumberSoK = new SerialNumberSignatureOfKnowledge(params, coin, fullCommitmentToCoinUnderSerialParams, hashSig, randomNumbers);

        // 5. Sign the transaction using the private key associated with the serial number
        if (version >= PUBKEY_VERSION) {
            this.pubKey = coin.getKeyPair();
            this.vchSig = this.pubKey.sign(Sha256Hash.wrap(hashSig.getReversedBytes())).encodeToDER();
            if (this.vchSig == null){
                throw new RuntimeException("Coinspend failed to sign signature hash");

            }
        }

    }

    public final byte[] signatureHash() {
        HashWriter h = new HashWriter();
        //h.print(true);
        h.write(serialCommitmentToCoinValue)
                .write(accCommitmentToCoinValue)
                .write(commitmentPoK)
                .write(accumulatorPoK)
                .write(pTxHash)
                .write(coinSerialNumber)
                .write(accChecksum.longValue())
                .write(denomination.getDenomination());
        ;
        if (version >= PUBKEY_VERSION) {
            h.writeInternal(new VarInt(spendType.ordinal()).encode());
        }
        return h.doubleShaReversed();
    }

    /**
     * Additional verification layer that requires the spend be signed by the private key associated with the serial
     */
    public boolean hasValidSignature() {
        //No private key for V1
        if (version < PUBKEY_VERSION)
            return true;

        //V2 serial requires that the signature hash be signed by the public key associated with the serial
        //TODO: This just check that the pubkey is the same that is used in the serial removing the v2 mark and checking the hashed key
        byte[] hashedPubKeyBites = Sha256Hash.twiceOf(pubKey.getPubKey()).getReversedBytes();
        //log.info("hashedPubKeyBytes: " + Hex.toHexString(hashedPubKeyBites));
        BigInteger hashedPubKey = new BigInteger(1, hashedPubKeyBites).shiftRight(V2_BITSHIFT);
        //log.info("hashedPubKey DEC: " + hashedPubKey);
        BigInteger adjustedSerial = getAdjustedSerial(coinSerialNumber);
        if (! ZUtils.equals(hashedPubKey , adjustedSerial)) {
            log.info("HasValidSignature() hashedpubkey is not equal to the serial!," +
                    "\n hashedPubKey: " + Hex.toHexString(hashedPubKey.toByteArray()) +
                    ",\nadjustedSerial: " + Hex.toHexString(adjustedSerial.toByteArray()) +
                    ",\ncoinSerialnumber: " + Hex.toHexString(coinSerialNumber.toByteArray()));
            return false;
        }

        return pubKey.verify(Utils.reverseBytes(signatureHash()), vchSig);
    }

    public boolean verify(Accumulator a) {
        // Double check that the version is the same as marked in the serial
        if (extractVersionFromSerial(coinSerialNumber) != version) {
            log.info( "CoinSpend::Verify: version does not match serial=" + extractVersionFromSerial(coinSerialNumber) + " actual=" + version + ", serial: " + coinSerialNumber.toString(16));
            return false;
        }

        if (a.getDenomination() != this.denomination) {
            log.info("CoinsSpend::Verify: failed, denominations do not match");
            return false;
        }

        // Verify both of the sub-proofs using the given meta-data
        if (!commitmentPoK.verify(serialCommitmentToCoinValue, accCommitmentToCoinValue)) {
            log.info("CoinsSpend::Verify: commitmentPoK failed");
            return false;
        }

        if (!accumulatorPoK.verify(a, accCommitmentToCoinValue)) {
            log.info("CoinsSpend::Verify: accumulatorPoK failed");
            return false;
        }

        byte[] signatureHash = signatureHash();
        if (!serialNumberSoK.verify(coinSerialNumber, serialCommitmentToCoinValue, Sha256Hash.wrap(signatureHash))) {
            log.info("CoinsSpend::Verify: serialNumberSoK failed. sighash: " + Hex.toHexString(signatureHash));
            return false;
        }

        return true;
    }

    @Override
    protected void parse() throws ProtocolException {

        this.denomination = CoinDenomination.fromValue((int) readUint32());
        this.pTxHash = readHash();
        this.accChecksum =  BigInteger.valueOf(readUint32());
        this.accCommitmentToCoinValue = readBignum();
        this.serialCommitmentToCoinValue = readBignum();
        this.coinSerialNumber = readBignum();
        this.accumulatorPoK = AccumulatorProofOfKnowledge.parse(params, zParams, payload, cursor, false);
        this.cursor = this.offset = this.accumulatorPoK.getCursor();
        this.serialNumberSoK = SerialNumberSignatureOfKnowledge.parse(params, zParams, payload, cursor, false);
        this.cursor = this.offset = this.serialNumberSoK.getCursor();
        this.commitmentPoK = CommitmentProofOfKnowledge.parse(
                params,
                zParams.getSerialNumberSoKCommitmentGroup(),
                zParams.getAccumulatorParams().getAccumulatorPoKCommitmentGroup(),
                payload,
                cursor,
                false
        );
        this.cursor = this.offset = this.commitmentPoK.getCursor();
        try {
            this.version = (int) readVarInt();
            this.pubKey = ECKey.fromPublicOnly(readByteArray());
            this.vchSig = readByteArray();
            this.spendType = SpendType.values()[(int) readVarInt()];
        }catch (Exception e){
            log.warn("Version 1 serial arrived??", this);
        }

        if (cursor != payload.length) throw new RuntimeException("There are more bytes to parse?");
    }

    @Override
    public byte[] bitcoinSerialize() {
        try (ByteArrayOutputStream buff = new ByteArrayOutputStream()) {
            Utils.uint32ToByteStreamLE(denomination.getDenomination(), buff);
            buff.write(pTxHash.getReversedBytes());
            Utils.uint32ToByteStreamLE(accChecksum.longValue(), buff);
            ZUtils.serializeBigInteger(buff, accCommitmentToCoinValue);
            ZUtils.serializeBigInteger(buff, serialCommitmentToCoinValue);
            ZUtils.serializeBigInteger(buff, coinSerialNumber);
            buff.write(accumulatorPoK.bitcoinSerialize());
            buff.write(serialNumberSoK.bitcoinSerialize());
            buff.write(commitmentPoK.bitcoinSerialize());
            buff.write(new VarInt(version).encode());
            serializeBytesVarInt(pubKey.getPubKey(), buff);
            serializeBytesVarInt(vchSig, buff);
            buff.write(new VarInt(spendType.ordinal()).encode());
            return buff.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize CoinSpend", e);
        }
    }


    public ZerocoinContext getzParams() {
        return zParams;
    }

    public CoinDenomination getDenomination() {
        return denomination;
    }

    public BigInteger getAccChecksum() {
        return accChecksum;
    }

    public Sha256Hash getpTxHash() {
        return pTxHash;
    }

    public BigInteger getAccCommitmentToCoinValue() {
        return accCommitmentToCoinValue;
    }

    public BigInteger getSerialCommitmentToCoinValue() {
        return serialCommitmentToCoinValue;
    }

    public BigInteger getCoinSerialNumber() {
        return coinSerialNumber;
    }

    public AccumulatorProofOfKnowledge getAccumulatorPoK() {
        return accumulatorPoK;
    }

    public SerialNumberSignatureOfKnowledge getSerialNumberSoK() {
        return serialNumberSoK;
    }

    public CommitmentProofOfKnowledge getCommitmentPoK() {
        return commitmentPoK;
    }

    public int getVersion() {
        return version;
    }

    public ECKey getPubKey() {
        return pubKey;
    }

    public byte[] getVchSig() {
        return vchSig;
    }

    public SpendType getSpendType() {
        return spendType;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CoinSpend coinSpend = (CoinSpend) o;
        return Arrays.equals(bitcoinSerialize(),coinSpend.bitcoinSerialize());
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(denomination, accChecksum, pTxHash, accCommitmentToCoinValue, serialCommitmentToCoinValue, coinSerialNumber, accumulatorPoK, serialNumberSoK, commitmentPoK, version, pubKey, spendType);
        result = 31 * result + Arrays.hashCode(vchSig);
        return result;
    }

    @Override
    public String toString() {
        return "CoinSpend{" +
                "zParams=" + zParams +
                ",\n denomination=" + denomination +
                ",\n accChecksum=" + accChecksum +
                ",\n pTxHash=" + pTxHash +
                ",\n accCommitmentToCoinValue=" + accCommitmentToCoinValue +
                ",\n serialCommitmentToCoinValue=" + serialCommitmentToCoinValue +
                ",\n coinSerialNumber=" + Hex.toHexString(coinSerialNumber.toByteArray()) +
                ",\n version=" + version +
                ",\n pubKey={pub:" + pubKey.getPublicKeyAsHex() +", priv:"+ ((pubKey.hasPrivKey()) ? pubKey.getPrivateKeyAsHex() : "null")+ "}"+
                ",\n vchSig=" + Hex.toHexString(vchSig) +
                ",\n spendType=" + spendType +
                ",\n accumulatorPoK=" + accumulatorPoK +
                ",\n serialNumberSoK=" + serialNumberSoK +
                ",\n commitmentPoK=" + commitmentPoK +
                '}';
    }
}
