// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core.accumulators;

import com.zerocoinj.core.ZeroCoin;
import com.zerocoinj.utils.ZUtils;
import org.pivxj.core.BlockChain;
import org.pivxj.core.Sha256Hash;
import org.pivxj.core.Transaction;
import org.pivxj.core.TransactionBag;
import org.pivxj.wallet.WalletTransaction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

/**
 * A witness that a PublicCoin is in the accumulation of a set of coins
 */
public class AccumulatorWitness {

    private static final Logger logger = LoggerFactory.getLogger(AccumulatorWitness.class);

    // Accumulator witness
    private Accumulator witness;
    private ZeroCoin element;

    /**  Construct's a witness.  You must add all elements after the witness
     * @param checkpoint the last known accumulator value before the element was added
     * @param coin the coin we want a witness to
     */
    public AccumulatorWitness(Accumulator checkpoint, ZeroCoin coin){
        this.witness = checkpoint.copy();
        this.element = coin;
    }


    /**
     *
     * TODO: Change the exception..
     * @param coin
     * @param transactionBag
     * @return
     * @throws Exception
     */
    public static AccumulatorWitness generateAccumulatorWitness(
            ZeroCoin coin,
            TransactionBag transactionBag,
            BlockChain blockChain) throws Exception {
            //Accumulator accumulator,
            //AccumulatorWitness& witness, int nSecurityLevel, int& nMintsAdded, string& strError, CBlockIndex* pindexCheckpoint){

        logger.info("Generating accumulator witness..");
        // Get the mint tx
        Sha256Hash parentTxId = coin.getParentTxId();
        Transaction mintTx = transactionBag.getTransactionPool(WalletTransaction.Pool.SPENT).get(parentTxId);

        if (mintTx == null){
            mintTx = transactionBag.getTransactionPool(WalletTransaction.Pool.PENDING).get(parentTxId);
            if (mintTx == null)
                throw new Exception("Mint tx not found for "+ parentTxId);
            else
                throw new Exception("Mint tx not confirmed by the network for "+ parentTxId);
        }

        // TODO: Need to get the block in which the mint was included into the blockchain
        // TODO: Use the block height appearence to get it
        //mintTx.getConfidence().getAppearedAtChainHeight();

        //StoredBlock mintedBlock = null;// blockChain.getBlockStore().get();

        //if (mintedBlock == null){
        //    throw new Exception("Block that minted the transactions doesn't exists on the blockstore, txid:  "+ parentTxId);
        //}

        int nHeightMintAdded = 1226445;//mintedBlock.getHeight();

        // Get the checkpoint added at the next multiple of 10
        int nHeightCheckpoint = nHeightMintAdded + (10 - (nHeightMintAdded % 10));

        // The height to start accumulating coins to add to witness
        int nAccStartHeight = nHeightMintAdded - (nHeightMintAdded % 10);

        // Get the accumulator that is right before the cluster of blocks containing our mint was added to the accumulator
        BigInteger bnAccValue = BigInteger.ZERO;
        //TODO: add here the block hash if i know it to speed up this process
        // as the database doesn't have a getBlockByHeight and only have the getBlock by hash.
        //if (getAccumulatorValue(nHeightCheckpoint, coin.getCoinDenomination())) {
        //    accumulator.setValue(bnAccValue);
        //    witness.resetValue(accumulator, coin);
        //}

        return null;
    }

    public void resetValue(Accumulator checkpoint, ZeroCoin coin) {
        this.witness.setValue(checkpoint.getValue());
        this.element = coin;
    }

    public void addElement(ZeroCoin coin) {
        if(!ZUtils.equals(element.getCommitment().getCommitmentValue(), coin.getCommitment().getCommitmentValue())) {
            witness.accumulate(coin);
        }
    }

    /**
     * Don't use this!
     * @param commitmentValue
     */
    public void addElementUnchecked(BigInteger commitmentValue) {
        if(!ZUtils.equals(element.getCommitment().getCommitmentValue(), commitmentValue)) {
            witness.increment(commitmentValue);
        }else {
            System.out.println("Trying to accumulate invalid coin");
        }
    }

    public BigInteger getValue() {
        return this.witness.getValue();
    }

    public boolean verifyWitness(Accumulator accumulator, ZeroCoin coin) {
        Accumulator temp = this.witness.copy();
        temp.accumulate(this.element);
        if (!temp.equals(accumulator)){
            logger.info("VerifyWitness: failed verify temp does not equal a\n");
            return false;
        } else if (!this.element.publicEquals(coin)){
            logger.info("VerifyWitness: failed verify pubCoins not equal\n");
            return false;
        }
        return true;
    }

}
