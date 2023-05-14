#include "Timer.h"
#include "Vanity.h"
#include "SECP256k1.h"
#include <iostream>
#include <string>
#include "hash/sha256.h"

using namespace std;

std::string toHex(unsigned char* data, int length);

int getRepetition(const Int& num, int maxBits)
{
    int count[16];
    memset(count, 0, sizeof(count));

    int bits = 0;
    for (int i = 0; i < 10; i++)
    {
        uint32_t v = num.bits[i];
        for (int j = 0; j < 32 / 4; j++)
        {
            uint8_t u = v & 0xF;
            count[u]++;
            v >>= 4;
            bits += 4;
            if (bits >= maxBits)
                break;
        }
        if (bits >= maxBits)
            break;
    }

    int m = 0;
    for (int i = 0; i < 16; i++)
        if (count[i] > m)
            m = count[i];

    return m;
}

int main(int argc, char **argv)
{
    // Global Init
    Timer::Init();
    rseed(Timer::getSeed32());

    // Init SecpK1
    Secp256K1* secp = new Secp256K1();
    secp->Init();

    char* privKeyStr = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5itSvZV2R4aJs65TTYmz";
    bool compressed;
    Int privKey = secp->DecodePrivateKey(privKeyStr, &compressed);
    string pAddr = secp->GetPrivAddress(compressed, privKey);

    unsigned char h0[20];
    int searchType = P2PKH;
    compressed = true;
    privKey.SetBase16("a1b2c3d4e1f2a3a4");
    privKey.SetInt32(0);

    double t0 = Timer::get_tick();
    Point pub = secp->ComputePublicKey(&privKey);
    const size_t kN = 65536ULL; // 4294967295ULL;
    size_t c = 0;
    for (size_t i = 0; i < kN; i++)
    {
        if (getRepetition(privKey, 16) > 1)
        {
            privKey.AddOne();
            continue;
        }

#if 1
        pub = secp->ComputePublicKey(&privKey);
        secp->GetHash160(searchType, compressed, pub, h0);
#endif

        //cout << "Public key hash: " << toHex(h0, 20) << endl;
        //std::string add = secp->GetAddress(P2PKH, compressed, h0);
        //cout << "BTC address:     " << secp->GetAddress(P2PKH, compressed, h0) << endl;
        privKey.AddOne();
        c++;
    }
    double t1 = Timer::get_tick();
    Timer::printResult((char*)"Key", kN, t0, t1);

    double p = c * 100. / kN;
    cout << "Processed " << c << " out of " << kN << " (" << p << ")" << endl;

    return 0;
}
