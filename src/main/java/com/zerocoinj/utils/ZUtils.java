// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.utils;

import com.zerocoinj.core.context.ZerocoinContext;
import org.pivxj.core.Utils;
import org.pivxj.core.VarInt;
import org.spongycastle.util.BigIntegers;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

public class ZUtils {

    public static final BigInteger BIGNUM_1 = BigInteger.ONE;
    public static final BigInteger BIGNUM_2 = new BigInteger("2");
    public static final BigInteger BIGNUM_3 = new BigInteger("3");
    public static final BigInteger BIGNUM_4 = new BigInteger("4");

    public static byte[] serializeBigInteger(BigInteger bigInteger){
        return Utils.reverseBytes(Utils.encodeMPI(bigInteger,false));
    }

    public static void serializeBigInteger(OutputStream buf, BigInteger bigInteger) throws IOException {
        byte[] num = ZUtils.serializeBigInteger(bigInteger);
        buf.write(new VarInt(num.length).encode());
        buf.write(num);
    }

    public static void serializeBytesVarInt(byte[] bytes, OutputStream buf) throws IOException {
        buf.write(new VarInt(bytes.length).encode());
        buf.write(bytes);
    }

    public static BigInteger unserialize(String hex) {
        return Utils.decodeMPI(Utils.reverseBytes(Hex.decode(hex)),false);
    }

    public static BigInteger unserializeBignum(byte[] buf) {
        return Utils.decodeMPI(Utils.reverseBytes(buf),false);
    }

    public static BigInteger random(BigInteger max){
        return BigIntegers.createRandomInRange(BigInteger.ZERO, max, ZerocoinContext.getSecureRandom());
    }

    public static BigInteger mul_mod(BigInteger one, BigInteger two, BigInteger mod){
        return one.multiply(two).mod(mod);
    }

    public static boolean isLessThan(BigInteger one, BigInteger two){
        return one.compareTo(two) < 0 ;
    }

    public static boolean isLessOrEqualThan(BigInteger one, BigInteger two){
        return one.compareTo(two) <= 0 ;
    }


    public static boolean isGreaterThan(BigInteger one, BigInteger two){
        return one.compareTo(two) > 0 ;
    }

    public static boolean isGreaterOrEqualThan(BigInteger one, BigInteger two){
        return one.compareTo(two) >= 0 ;
    }

    public static boolean equals(BigInteger value1, BigInteger value2) {
        return value1.compareTo(value2) == 0;
    }

    public static boolean isNegative(BigInteger bigInteger){
        return bigInteger.compareTo(BigInteger.ZERO) < 0;
    }

    public static boolean isZero(BigInteger bigInteger) {
        return bigInteger.compareTo(BigInteger.ZERO) == 0;
    }
}
