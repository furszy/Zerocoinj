// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core;

import org.pivxj.core.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;

import static org.pivxj.core.Utils.uint32ToByteArrayBE;

public class HashWriter extends FStream<HashWriter>{

    private Logger logger = LoggerFactory.getLogger(HashWriter.class);

    private SHA256Digest sha256Digest;
    //
    private boolean print;

    public HashWriter() {
        this.sha256Digest = new SHA256Digest();
    }

    public void writeInternal(byte[] buffer){
        if (print)
            logger.info("Writing data (internal): " + Hex.toHexString(buffer));
        sha256Digest.update(buffer, 0 , buffer.length);
    }

    public byte[] doubleShaReversed(){
        byte[] buf = new byte[32];
        sha256Digest.doFinal(buf, 0);
        sha256Digest.reset();
        sha256Digest.update(buf, 0, buf.length);
        sha256Digest.doFinal(buf, 0);
        return Utils.reverseBytes(buf);
    }

    public static BigInteger toUint256(byte[] out){
        int length = out.length;
        boolean isNegative = (out[0] & 128) == 128;
        if ((out[0] & 128) == 128) {
            ++length;
        }
        byte[] result;
        result = new byte[length + 4];
        System.arraycopy(out, 0, result, length - out.length + 4, out.length);
        uint32ToByteArrayBE((long) length, result, 0);
        if (isNegative) {
            result[4] = (byte) (result[4] | 128);
        }
        return Utils.decodeMPI(result,true);
    }

    public BigInteger toUint256(byte[] toConvert, boolean includeLenght){
        try {
            byte[] out = (toConvert != null) ? toConvert : doubleShaReversed();

            boolean isNegative = (out[0] & 128) == 128;
            int length = out.length;
            if ((out[0] & 128) == 128) {
                ++length;
            }


            byte[] result;
            if (includeLenght) {
                result = new byte[length + 4];
                System.arraycopy(out, 0, result, length - out.length + 4, out.length);
                uint32ToByteArrayBE((long) length, result, 0);
                if (isNegative) {
                    result[4] = (byte) (result[4] | 128);
                }
            }else {
                if (length != out.length) {
                    result = new byte[length];
                    System.arraycopy(out, 0, result, 1, out.length);
                } else {
                    result = out;
                }

                if (isNegative) {
                    result[0] = (byte)(result[0] | 128);
                }
                if (result.length == 33 && result[0] == 0){
                    byte[] temp = new byte[32];
                    System.arraycopy(result,1,temp,0,32);
                    result = temp;
                }
            }
            return Utils.decodeMPI(result,includeLenght);
        }catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public void print(boolean print) {
        this.print = print;
    }
}
