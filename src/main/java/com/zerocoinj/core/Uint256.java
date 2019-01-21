// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core;

import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;

public class Uint256 {

    private static final BigInteger TWO_COMPL_REF = BigInteger.ONE.shiftLeft(256);

    private static final int BYTES = 32;

    private byte[] value;

    public Uint256(byte[] value) {
        this.value = value;
        checkValid();
    }

    public Uint256 shiftRight(int n){
        value = new BigInteger(Hex.toHexString(value),16).shiftRight(n).toByteArray();
        checkValid();
        return this;
    }

    public byte[] getValue() {
        return value;
    }

    public BigInteger getBigIntegerValue() {
        return new BigInteger(value);
    }

    public String toHex(){
        return Hex.toHexString(value);
    }

    private void checkValid(){
        if (value.length != BYTES) throw new IllegalArgumentException("value has not 32 bytes");
    }


    public static byte[] parseBigIntegerPositive(BigInteger b) {
        if (b.compareTo(BigInteger.ZERO) < 0)
            b = b.add(TWO_COMPL_REF);

        return b.toByteArray();
    }
}
