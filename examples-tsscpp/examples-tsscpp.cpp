// examples-tsscpp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
//
#include <iostream>
#include <Tpm2.h>
#include <TpmDevice.h>
#include <TpmTypes.h>

using namespace std;
using namespace TpmCpp;

Tpm2 tpm;
TpmTbsDevice deviceTbs;
TpmTcpDevice deviceTcp;

bool useSimulator = true;

int InitTpm() {
    if (useSimulator) {
        if (!deviceTcp.Connect("127.0.0.1", 2321)) {
            cerr << "Could not connect to the TPM TCP device\n";
            return -1;
        }
        tpm._SetDevice(deviceTcp);
        deviceTcp.PowerOff();
        deviceTcp.PowerOn();
        tpm.Startup(TPM_SU::CLEAR);
        return 0;
    }

    if (!deviceTbs.Connect()) {
        cerr << "Could not connect to the TPM TBS device\n";
        return -1;
    }

    tpm._SetDevice(deviceTbs);
    return 0;
}

int ShutdownTpmSimulator() {
    if (!useSimulator) {
        cerr << "You are not using TPM Simulator\n";
        return -1;
    }

    tpm.Shutdown(TPM_SU::CLEAR);
    deviceTcp.PowerOff();
    return 0;
}

void TestDifferentDataStructures()
{
    bool singlePcr = true;
    PCR_ReadResponse pcrVal;

    if (singlePcr) {
        UINT32 pcrIndex = 0;

        // "Event" PCR-0 with the binary data
        tpm.PCR_Event(pcrIndex, tpm.GetRandom(5));

        // Read PCR-0
        vector<TPMS_PCR_SELECTION> pcrToRead{ TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, pcrIndex) };

        pcrVal = tpm.PCR_Read(pcrToRead);
    }
    else {
        vector<UINT32> pcrIndexes = { 0, 1, 2, 3, 4 };

        for (UINT32 pcr : pcrIndexes) {
            tpm.PCR_Event(pcr, tpm.GetRandom(5));
        }

        vector<TPMS_PCR_SELECTION> pcrToRead{ TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, pcrIndexes) };

        pcrVal = tpm.PCR_Read(pcrToRead);
    }

    // Now print it out in pretty-printed human-readable form
    cout << "Text form of pcrVal" << endl << pcrVal.ToString() << endl;

    // Now in JSON
    string pcrValInJSON = pcrVal.Serialize(SerializationType::JSON);
    cout << "JSON form" << endl << pcrValInJSON << endl;

    // Now in TPM-binary form
    vector<BYTE> tpmBinaryForm = pcrVal.toBytes();
    cout << "TPM Binary form:" << endl << tpmBinaryForm << endl;

    // Now rehydrate the JSON and binary forms to new structures
    PCR_ReadResponse fromJSON, fromBinary;
    fromJSON.Deserialize(SerializationType::JSON, pcrValInJSON);
    fromBinary.initFromBytes(tpmBinaryForm);

    // And check that the reconstituted values are the same as the originals with
    // the built-in value-equality operators.

    cout << "JSON Deserialization " << (pcrVal == fromJSON ? "succeeded" : "failed") << endl;
    cout << "Binary Deserialization " << (pcrVal == fromBinary ? "succeeded" : "failed") << endl;

    return;
}

void GenerateRandomNumbers() {
    std::vector<BYTE> rand = tpm.GetRandom(20);

    cout << "Random bytes: " << rand << endl;
}

void HMACSessions()
{
    // Start a simple HMAC authorization session: no salt, no encryption, no bound-object.
    AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::HMAC, TPM_ALG_ID::SHA1);

    cout << "Session Infos:\n\n";

    cout << "Is PWAP: " << s.IsPWAP() << endl;
    cout << "Nonce: " << s.GetNonceTpm() << endl;
    cout << "Hash algorithm: " << s.GetHashAlg() << endl;

    // Perform an operation authorizing with an HMAC
    tpm._Sessions(s).Clear(tpm._AdminPlatform);

    // A more terse way of associating an explicit session with a command
    tpm(s).Clear(tpm._AdminPlatform);

    // And clean up
    tpm.FlushContext(s);

    return;
}

int main()
{
    InitTpm();

    cout << "Hello World!\n";
    cout << "You are using a " << (useSimulator ? "TCP" : "TBS") << " device!\n\n";

    GenerateRandomNumbers();
    TestDifferentDataStructures();
    HMACSessions();

    if (useSimulator) {
        ShutdownTpmSimulator();
    }
}
