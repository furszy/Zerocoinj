// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj;

import com.zerocoinj.base.BaseZerocoinTest;
import com.zerocoinj.core.Commitment;
import com.zerocoinj.core.CommitmentProofOfKnowledge;
import com.zerocoinj.utils.ZUtils;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class EqualityPoKTest extends BaseZerocoinTest {

    @Test
    public void equalityPoKTest(){

        // Run this test 10 times
        for (int i = 0; i < 10; i++) {

            // Generate a random integer "val"
            BigInteger val = ZUtils.random(zerocoinContext.getCoinCommitmentGroup().getGroupOrder());

            // Manufacture two commitments to "val", both
            // under different sets of parameters
            Commitment one = new Commitment(
                    val,
                    zerocoinContext.getAccumulatorParams().getAccumulatorPoKCommitmentGroup()
            );

            Commitment two = new Commitment(
                    val,
                    zerocoinContext.getSerialNumberSoKCommitmentGroup()
            );

            // Now generate a proof of knowledge that "one" and "two" are
            // both commitments to the same value
            CommitmentProofOfKnowledge pok = new CommitmentProofOfKnowledge(
                    zerocoinContext.getAccumulatorParams().getAccumulatorPoKCommitmentGroup(),
                    zerocoinContext.getSerialNumberSoKCommitmentGroup(),
                    one, two);


            if (!pok.verify(one.getCommitmentValue(), two.getCommitmentValue())) {
                Assert.fail("Not valid PoK");
            }

        }
    }
}
