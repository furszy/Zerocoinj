// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core.accumulators;

import com.google.common.base.Preconditions;
import com.zerocoinj.core.CoinDenomination;
import com.zerocoinj.core.ZeroCoin;
import com.zerocoinj.core.context.AccumulatorAndProofParams;
import com.zerocoinj.utils.ZUtils;
import org.pivxj.core.Message;
import org.pivxj.core.NetworkParameters;
import org.pivxj.core.ProtocolException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Implementation of the RSA-based accumulator
 */
public class Accumulator extends Message {

    private static final Logger log = LoggerFactory.getLogger(Accumulator.class);

    // Context
    private AccumulatorAndProofParams accAndProofOfParams;
    // Accumulator denomination
    private CoinDenomination denomination;
    // Accumulator value
    private BigInteger value;


    public static Accumulator parse(NetworkParameters params, AccumulatorAndProofParams accAndProofOfParams, byte[] payload){
        Accumulator acc = new Accumulator(params);
        acc.accAndProofOfParams = accAndProofOfParams;
        // Add protocol if i need it in the future
        //sok.protocolVersion = protocolVersion;
        acc.payload = payload;
        acc.cursor = acc.offset = 0;
        acc.length = payload.length;

        acc.parse();

        if (acc.length == UNKNOWN_LENGTH) {
            Preconditions.checkState(false, "Length field has not been set in constructor for %s after parse.", acc.getClass().getSimpleName());
        }

        if (!acc.serializer.isParseRetainMode()) {
            acc.payload = null;
        }
        return acc;
    }

    private Accumulator(NetworkParameters params) {
        super(params);
    }
    /**
     * @brief Construct an Accumulator from a Params object.
     * @param params    A Params object containing global parameters
     * @param denomination the denomination of coins we are accumulating
     **/
    public Accumulator(AccumulatorAndProofParams params, CoinDenomination denomination) {
        this.accAndProofOfParams = params;
        this.denomination = denomination;
        this.value = params.getAccumulatorBase();
    }

    public Accumulator(AccumulatorAndProofParams params, CoinDenomination denomination, BigInteger value) {
        this.accAndProofOfParams = params;
        this.denomination = denomination;
        this.value = value;
    }

    public Accumulator copy(){
        return new Accumulator(this.accAndProofOfParams, this.denomination, this.value);
    }

    public void setValue(final BigInteger value) {
        this.value = value;
    }

    public BigInteger getValue() {
        return value;
    }

    void increment(final BigInteger bnValue) {
        // Compute new accumulator = "old accumulator"^{element} mod N
        this.value = this.value.modPow(bnValue, this.accAndProofOfParams.getAccumulatorModulus());
    }

    public Accumulator accumulate(ZeroCoin coin) {
        // Make sure we're initialized
        if(this.value == null) {
            log.warn("Accumulator is not initialized");
            throw new RuntimeException("Accumulator is not initialized");
        }

        if(this.denomination != coin.getCoinDenomination()) {
            log.info(String.format(
                    "Wrong denomination for coin. Expected coins of denomination: %s . Instead, got a coin of denomination: %s",
                    this.denomination, coin.getCoinDenomination()
            ));
            throw new RuntimeException("Wrong denomination for coin");
        }

        if(coin.validate()) {
            increment(coin.getCommitment().getCommitmentValue());
        } else {
            log.info("Coin not valid: " + coin);
            throw new RuntimeException("Coin is not valid");
        }
        return this;
    }

    public CoinDenomination getDenomination() {
        return denomination;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Accumulator that = (Accumulator) o;
        return denomination == that.denomination &&
                ZUtils.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(denomination, value);
    }

    @Override
    protected void parse() throws ProtocolException {
        this.value = readBignum();
        this.denomination = CoinDenomination.fromValue((int) readUint32());
    }

    @Override
    public String toString() {
        return "value=" + value +", denomination=" + denomination;
    }
}
