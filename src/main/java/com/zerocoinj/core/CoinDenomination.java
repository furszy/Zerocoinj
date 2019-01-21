// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package com.zerocoinj.core;

import org.pivxj.core.Coin;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public enum CoinDenomination {

    ZQ_ERROR(0),
    ZQ_ONE(1),
    ZQ_FIVE(5),
    ZQ_TEN(10),
    ZQ_FIFTY(50),
    ZQ_ONE_HUNDRED(100),
    ZQ_FIVE_HUNDRED(500),
    ZQ_ONE_THOUSAND(1000),
    ZQ_FIVE_THOUSAND(5000);

    private int denomination;
    private Coin value;

    CoinDenomination(int denomination) {
        this.denomination = denomination;
        this.value = Coin.parseCoin(String.valueOf(denomination));
    }

    public int getDenomination() {
        return this.denomination;
    }

    public static CoinDenomination fromValue(int value) {
        CoinDenomination[] var1 = values();
        int var2 = var1.length;

        for(int var3 = 0; var3 < var2; ++var3) {
            CoinDenomination coinDenomination = var1[var3];
            if (coinDenomination.denomination == value) {
                return coinDenomination;
            }
        }

        throw new IllegalArgumentException("Coin denomination doesn't exists for " + value);
    }

    public static CoinDenomination[] invertedValues(){
        List<CoinDenomination> list = Arrays.asList(values());
        Collections.reverse(list);
        return (CoinDenomination[]) list.toArray();

    }


    @Override
    public String toString() {
        return "denomination=" + denomination +
                ", value=" + value;
    }

}