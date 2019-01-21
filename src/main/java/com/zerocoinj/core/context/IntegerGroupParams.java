// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core.context;

import java.math.BigInteger;

public class IntegerGroupParams {

    boolean isInitialized;

    /**
     * A generator for the group.
     */
    private BigInteger g;

    /**
     * A second generator for the group.
     * Note log_g(h) and log_h(g) must
     * be unknown.
     */
    private BigInteger h;

    /**
     * The modulus for the group.
     */
    private BigInteger modulus;

    /**
     * The order of the group
     */
    private BigInteger groupOrder;

    public IntegerGroupParams(BigInteger g, BigInteger h, BigInteger modulus, BigInteger groupOrder) {
        this.g = g;
        this.h = h;
        this.modulus = modulus;
        this.groupOrder = groupOrder;
        //TODO: el metodo deriveIntegerGroupParams del core de pivx no inicializa esto..
        this.isInitialized = false;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getH() {
        return h;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getGroupOrder() {
        return groupOrder;
    }

    public boolean isInitialized() {
        return isInitialized;
    }

    @Override
    public String toString() {
        return "IntegerGroupParams{" +
                "g=" + g +
                ", h=" + h +
                ", modulus=" + modulus +
                ", groupOrder=" + groupOrder +
                '}';
    }


}
