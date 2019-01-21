// Copyright (c) 2019 Matias Furszyfer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "com_zerocoinj_JniBridge.h"
#include "version.h"
#include "uint256.h"
#include "hash.h"
#include "libzerocoin/bignum.h"
#include <iostream>
#include <string>
#include <sstream>
#include <exception>
#include <stdexcept>

JNIEXPORT jbyteArray JNICALL Java_com_zerocoinj_JniBridge_compute1024seed
  (JNIEnv * env, jobject obj, jbyteArray seed){

    try{

        int len = env->GetArrayLength (seed);
        unsigned char* buf = new unsigned char[len];
        env->GetByteArrayRegion (seed, 0, len, reinterpret_cast<jbyte*>(buf));
        std::vector<unsigned char> __c_vec(buf,buf + len);

        CBigNum num(__c_vec);
        uint256 hashSeed = num.getuint256();

        CHashWriter hasher(0,0);
        hasher << hashSeed;

        vector<unsigned char> vResult;
        for (int i = 0; i < 4; i ++) {
            uint256 hash = hasher.GetHash();
            vector<unsigned char> vHash = CBigNum(hash).getvch();
            vResult.insert(vResult.end(), vHash.begin(), vHash.end());
            hasher << vResult;
        }

        CBigNum bnResult;
        bnResult.setvch(vResult);

        std::vector<unsigned char> vch = bnResult.getvch();
        jbyteArray ret = env->NewByteArray (vch.size());
        env->SetByteArrayRegion (ret, 0, vch.size(), reinterpret_cast<jbyte*>(vch.data()));
        return ret;

    }catch (const std::exception &exc){
         // catch anything thrown within try block that derives from std::exception
         std::cout << "Exception: " << exc.what() << std::endl;
         return NULL;
    }
  }



  JNIEXPORT jstring JNICALL Java_com_zerocoinj_JniBridge_computeVSeedAndVExpanded
    (JNIEnv * env, jobject obj){

        uint256 notNum = ~uint256(0);
        CBigNum notZeroBigNum(notNum);
        CBigNum randBignum = CBigNum::randBignum(notZeroBigNum);
        uint256 hashRand = randBignum.getuint256();

        uint256 hashSeed = hashRand;

        CHashWriter hasher(0,0);
        hasher << hashSeed;

        vector<unsigned char> vResult;
        for (int i = 0; i < 4; i ++) {
            uint256 hash = hasher.GetHash();
            vector<unsigned char> vHash = CBigNum(hash).getvch();
            vResult.insert(vResult.end(), vHash.begin(), vHash.end());
            hasher << vResult;
        }


        CBigNum bnExpanded;
        bnExpanded.setvch(vResult);

        CBigNum vSeed = CBigNum(hashRand);
        CBigNum vExpanded = bnExpanded;

        std::stringstream ret;
        ret << vSeed.GetDec();
        ret << "||";
        ret << vExpanded.GetDec();

        // Success! We're done.
        return (*env).NewStringUTF(ret.str().data());
    }