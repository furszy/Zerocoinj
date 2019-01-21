// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core;

import com.zerocoinj.core.accumulators.AccumulatorProofOfKnowledge;
import com.zerocoinj.core.context.AccumulatorAndProofParams;
import com.zerocoinj.core.context.IntegerGroupParams;
import com.zerocoinj.core.context.ZerocoinContext;
import org.pivxj.core.Sha256Hash;
import org.pivxj.core.Utils;
import org.pivxj.core.VarInt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

public abstract class FStream<C extends FStream<C>> {

    public C write(boolean b) {
        byte bytes = (byte) (b ? 1:0);
        byte[] array = new byte[]{bytes};
        writeInternal(array);
        return (C) this;
    }

    public C write(BigInteger bigInteger){
        byte[] bigIntBytes = Utils.reverseBytes(Utils.encodeMPI(bigInteger, false));
        writeCompactSize(bigIntBytes);
        return (C) this;
    }

    public C write(byte[] bytes){
        writeCompactSize(bytes);
        return (C) this;
    }

    public C write(int num){
        byte[] buffer = new byte[4];
        Utils.uint32ToByteArrayLE(num, buffer, 0);
        writeInternal(buffer);
        return (C) this;
    }

    public C write(long l) {
        byte[] buffer = new byte[4];
        Utils.uint32ToByteArrayLE(l,buffer,0);
        writeInternal(buffer);
        return (C) this;
    }

    public C write(String str) throws UnsupportedEncodingException {
        byte[] buffer = str.getBytes("UTF-8");
        writeCompactSize(buffer);
        return (C) this;
    }

    public C write(Sha256Hash sha256Hash){
        // TODO: Check me..
        if (sha256Hash == null){
            writeInternal(Sha256Hash.wrap(new byte[32]).getBytes());
        }else
            writeInternal(sha256Hash.getReversedBytes());
        return (C) this;
    }

    public C write(IntegerGroupParams groupParams){
        write(groupParams.isInitialized());
        write(groupParams.getG());
        write(groupParams.getH());
        write(groupParams.getModulus());
        write(groupParams.getGroupOrder());
        return (C) this;
    }

    public C write(ZerocoinContext params) {
        write(params.isInitialized());
        write(params.getAccumulatorParams());
        write(params.getCoinCommitmentGroup());
        write(params.getSerialNumberSoKCommitmentGroup());
        write(params.getZkp_iterations());
        write(params.getZkp_hash_len());
        return (C) this;
    }

    public C write(AccumulatorProofOfKnowledge params){
        write(params.C_e);
        write(params.C_u);
        write(params.C_r);
        write(params.st_1);
        write(params.st_2);
        write(params.st_3);
        write(params.t_1);
        write(params.t_2);
        write(params.t_3);
        write(params.t_4);
        write(params.s_alpha);
        write(params.s_beta);
        write(params.s_zeta);
        write(params.s_sigma);
        write(params.s_eta);
        write(params.s_epsilon);
        write(params.s_delta);
        write(params.s_xi);
        write(params.s_phi);
        write(params.s_gamma);
        write(params.s_psi);
        return (C) this;
    }

    public C write(CommitmentProofOfKnowledge params){
        write(params.getS1());
        write(params.getS2());
        write(params.getS3());
        write(params.getChallenge());
        return (C) this;
    }

    public C write(AccumulatorAndProofParams params) {
        write(params.isInitialized());
        write(params.getAccumulatorModulus());
        write(params.getAccumulatorBase());
        write(params.getAccumulatorPoKCommitmentGroup());
        write(params.getAccumulatorQRNCommitmentGroup());
        write(params.getMinCoinValue());
        write(params.getMaxCoinValue());
        write(params.getK_prime());
        write(params.getK_dprime());
        return (C) this;
    }

    private void writeCompactSize(byte[] buffer) {
        int nSize = buffer.length;
        if (nSize < 253) {
            write(buffer,0);
        } else{
            byte[] b = new VarInt(buffer.length).encode();
            writeInternal(b);
            writeInternal(buffer);
        }
    }

    /**
     * TODO: Check if i really need this method.. 100% sure that i don't need it anymore..
     * @param buffer
     * @param extraSpace
     */
    public void write(byte[] buffer, int extraSpace) {
        byte[] lengthArray = null;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(buffer.length);
        close(byteArrayOutputStream);
        lengthArray = byteArrayOutputStream.toByteArray();
        writeInternal(lengthArray);
        //if (buffer.length == 0) writeInternal(lengthArray);
        writeInternal(buffer);
    }

    private void close(ByteArrayOutputStream byteArrayOutputStream) {
        try {
            byteArrayOutputStream.close();
        } catch (IOException e) {
            // nothing..
        }
    }

    public abstract void writeInternal(byte[] buf);
}
