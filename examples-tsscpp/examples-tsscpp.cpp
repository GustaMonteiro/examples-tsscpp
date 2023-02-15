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
static const TPMT_SYM_DEF_OBJECT Aes128Cfb{ TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };

TPM_HANDLE MakeStoragePrimary(AUTH_SESSION* sess)
{

    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        {},           // No policy
        TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
    // Create the key
    if (sess)
        tpm[*sess];
    return tpm.CreatePrimary(TPM_RH::OWNER, {}, storagePrimaryTemplate, {}, {})
        .handle;
}

TPM_HANDLE MakeEndorsementKey()
{
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        {},           // No policy
        TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
    // Create the key
    return tpm.CreatePrimary(TPM_RH::ENDORSEMENT, {}, storagePrimaryTemplate, {}, {})
        .handle;
}

void RsaEncryptDecrypt()
{
    
    // This sample demostrates the use of the TPM for RSA operations.

    // We will make a key in the "{} hierarchy".
    TPMT_PUBLIC primTempl(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin,
        {},  // No policy
        TPMS_RSA_PARMS({}, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());

    // Create the key
    auto storagePrimary = tpm.CreatePrimary(TPM_RH_NULL, {}, primTempl, {}, {});

    TPM_HANDLE& keyHandle = storagePrimary.handle;

    ByteVec dataToEncrypt = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA1, "secret");
    cout << "Data to encrypt: " << dataToEncrypt << endl;

    auto enc = tpm.RSA_Encrypt(keyHandle, dataToEncrypt, TPMS_NULL_ASYM_SCHEME(), {});
    cout << "RSA-encrypted data: " << enc << endl;

    auto dec = tpm.RSA_Decrypt(keyHandle, enc, TPMS_NULL_ASYM_SCHEME(), {});
    cout << "decrypted data: " << dec << endl;
    if (dec == dataToEncrypt)
        cout << "Decryption worked" << endl;
    _ASSERT(dataToEncrypt == dec);

    // Now encrypt using TSS.C++ library functions
    ByteVec mySecret = Helpers::RandomBytes(20);
    enc = storagePrimary.outPublic.Encrypt(mySecret, {});
    dec = tpm.RSA_Decrypt(keyHandle, enc, TPMS_NULL_ASYM_SCHEME(), {});
    cout << "My           secret: " << mySecret << endl;
    cout << "My decrypted secret: " << dec << endl;
    _ASSERT(mySecret == dec);

    // Now with padding
    ByteVec pad{ 1, 2, 3, 4, 5, 6, 0 };
    enc = storagePrimary.outPublic.Encrypt(mySecret, pad);
    dec = tpm.RSA_Decrypt(keyHandle, enc, TPMS_NULL_ASYM_SCHEME(), pad);
    cout << "My           secret: " << mySecret << endl;
    cout << "My decrypted secret: " << dec << endl;
    _ASSERT(mySecret == dec);

    tpm.FlushContext(keyHandle);
} // RsaEncryptDecrypt()

void Hash()
{
    vector<TPM_ALG_ID> hashAlgs = { TPM_ALG_ID::SHA1, TPM_ALG_ID::SHA256 };
    ByteVec accumulator;
    ByteVec data1{ 1, 2, 3, 4, 5, 6 };

    cout << "Simple Hashing" << endl;

    for (auto it = hashAlgs.begin(); it != hashAlgs.end(); it++)
    {
        auto hashResponse = tpm.Hash(data1, *it, TPM_RH_NULL);
        auto expected = Crypto::Hash(*it, data1);

        _ASSERT(hashResponse.outHash == expected);
        cout << "Hash:: " << EnumToStr(*it) << endl;
        cout << "Expected:      " << expected << endl;
        cout << "TPM generated: " << hashResponse.outHash << endl;
    }

    cout << "Hash sequences" << endl;

    for (auto iterator = hashAlgs.begin(); iterator != hashAlgs.end(); iterator++) {
        auto hashHandle = tpm.HashSequenceStart({}, *iterator);
        accumulator.clear();

        for (int j = 0; j < 10; j++) {
            // Note the syntax below. If no explicit sessions are provided then the
            // library automatically uses PWAP with the authValue contained in the handle.
            // If you want to mix PWAP and other sessions then you can use the psuedo-PWAP
            // session as below.
            AUTH_SESSION mySession = AUTH_SESSION::PWAP();
            tpm[mySession].SequenceUpdate(hashHandle, data1);
            accumulator = Helpers::Concatenate(accumulator, data1);
        }

        accumulator = Helpers::Concatenate(accumulator, data1);

        // Note that the handle is flushed by the TPM when the sequence is completed
        auto hashVal = tpm.SequenceComplete(hashHandle, data1, TPM_RH_NULL);
        auto expected = Crypto::Hash(*iterator, accumulator);

        _ASSERT(hashVal.result == expected);
        cout << "Hash:: " << EnumToStr(*iterator) << endl;
        cout << "Expected:      " << expected << endl;
        cout << "TPM generated: " << hashVal.result << endl;
    }

    // We can also do an "event sequence"
    auto hashHandle = tpm.HashSequenceStart({}, TPM_ALG_NULL);
    accumulator.clear();

    for (int j = 0; j < 10; j++) {
        tpm.SequenceUpdate(hashHandle, data1);
        accumulator = Helpers::Concatenate(accumulator, data1);
    }

    accumulator = Helpers::Concatenate(accumulator, data1);

    // Note that the handle is flushed by the TPM when the sequence is completed
    auto initPcr = tpm.PCR_Read({ {TPM_ALG_ID::SHA1, 0} });
    auto hashVal2 = tpm.EventSequenceComplete(TPM_HANDLE::Pcr(0), hashHandle, data1);
    auto expected = Crypto::Hash(TPM_ALG_ID::SHA1, accumulator);
    auto finalPcr = tpm.PCR_Read({ {TPM_ALG_ID::SHA1, 0} });

    // Is this what we expect?
    TPM_HASH expectedPcr(TPM_ALG_ID::SHA1, initPcr.pcrValues[0]);
    expectedPcr.Extend(expected);

    if (expectedPcr == finalPcr.pcrValues[0])
        cout << "EventSequenceComplete gives expected answer:  " << endl << expectedPcr.ToString(false) << endl;
    _ASSERT(expectedPcr == finalPcr.pcrValues[0]);
} // Hash()

void PrimaryKeys()
{
    // To create a primary key the TPM must be provided with a template.
    // This is for an RSA1024 signing key.
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        {},  // No policy
        TPMS_RSA_PARMS({}, TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 1024, 65537),
        TPM2B_PUBLIC_KEY_RSA());

    // Set the use-auth for the nex key. Note the second parameter is
    // NULL because we are asking the TPM to create a new key.
    ByteVec userAuth = { 1, 2, 3, 4 };
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, {});

    // Create the key (no PCR-state captured)
    auto newPrimary = tpm._AllowErrors()
        .CreatePrimary(TPM_RH::OWNER, sensCreate, templ, {}, {});
    if (!tpm._LastCommandSucceeded())
    {
        // Some TPMs only allow primary keys of no lower than a particular strength.
        _ASSERT(tpm._GetLastResponseCode() == TPM_RC::VALUE);
        dynamic_cast<TPMS_RSA_PARMS*>(&*templ.parameters)->keyBits = 2048;
        newPrimary = tpm.CreatePrimary(TPM_RH::OWNER, sensCreate, templ, {}, {});
    }

    // Print out the public data for the new key. Note the parameter to
    // ToString() "pretty-prints" the byte-arrays.
    cout << "New RSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;

    cout << "Name of new key:" << endl;
    cout << " Returned by TPM " << newPrimary.name << endl;
    cout << " Calculated      " << newPrimary.outPublic.GetName() << endl;
    cout << " Set in handle   " << newPrimary.handle.GetName() << endl;
    _ASSERT(newPrimary.name == newPrimary.outPublic.GetName());

    // Sign something with the new key.  First set the auth-value in the handle
    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);

    //TPM_HASH dataToSign = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA256, "abc");

    //auto sig = tpm.Sign(signKey, dataToSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());
    //cout << "Data to be signed:" << dataToSign.digest << endl;
    //cout << "Signature:" << endl << sig->ToString(false) << endl;

    // We can put the primary key into NV with EvictControl
    TPM_HANDLE persistentHandle = TPM_HANDLE::Persistent(1000);

    // First delete anything that might already be there
    tpm._AllowErrors().EvictControl(TPM_RH::OWNER, persistentHandle, persistentHandle);

    // Make our primary persistent
    tpm.EvictControl(TPM_RH::OWNER, newPrimary.handle, persistentHandle);

    // Flush the old one
    tpm.FlushContext(newPrimary.handle);

    // ReadPublic of the new persistent one
    auto persistentPub = tpm.ReadPublic(persistentHandle);
    cout << "Public part of persistent primary" << endl << persistentPub.ToString(false);

    // And delete it
    tpm.EvictControl(TPM_RH::OWNER, persistentHandle, persistentHandle);
} // PrimaryKeys()

void SigningPrimary()
{
    // To create a primary key the TPM must be provided with a template.
    // This is for an RSA1024 signing key.
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::sign |
        TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM |
        TPMA_OBJECT::sensitiveDataOrigin |
        TPMA_OBJECT::userWithAuth,
        {},
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT(),
            TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 1024, 65537),
        TPM2B_PUBLIC_KEY_RSA());

    // Set the use-auth for the key. Note the second parameter is NULL
    // because we are asking the TPM to create a new key.
    ByteVec userAuth = ByteVec{ 1, 2, 3, 4 };
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, {});

    // We don't need to know the PCR-state with the key was created so set this
    // parameter to a {}-vector.
    std::vector<TPMS_PCR_SELECTION> pcrSelect;

    // Ask the TPM to create the key
    auto newPrimary = tpm.CreatePrimary(TPM_RH::OWNER, sensCreate, templ, {}, pcrSelect);

    // Print out the public data for the new key. Note the "false" parameter to
    // ToString() "pretty-prints" the byte-arrays.
    cout << "New RSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;
    cout << endl << "endl:" << endl << newPrimary.outPublic.unique.get() << endl << endl << endl;

    // Sign something with the new key. First set the auth-value in the handle.
    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);

    TPM_HASH dataToSign = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA1, "abc");

    auto sig = tpm.Sign(signKey, dataToSign, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());

    cout << "Signature:" << endl << sig->ToString() << endl;

    // Use TSS.C++ to validate the signature
    bool sigOk = newPrimary.outPublic.ValidateSignature(dataToSign, *sig);
    cout << "Signature is " << (sigOk ? "OK" : "BAD") << endl;
    _ASSERT(sigOk);

    tpm.FlushContext(newPrimary.handle);
} // SigningPrimary()

int main()
{
    InitTpm();

    cout << "Hello World!\n";
    cout << "You are using a " << (useSimulator ? "TCP" : "TBS") << " device!\n\n";

    //GenerateRandomNumbers(); // working
    //TestDifferentDataStructures(); // working
    //HMACSessions(); // working
    //Hash(); // working

    //TPM_HANDLE primaryKey = MakeStoragePrimary(NULL);
    //cout << primaryKey.Serialize(SerializationType::JSON) << endl;

    //RsaEncryptDecrypt();
    //PrimaryKeys(); // working
    //SigningPrimary();

    //TPM_HANDLE ekHandle = MakeEndorsementKey();
    //cout << ekHandle.handle << endl;


    if (useSimulator) {
        ShutdownTpmSimulator();
    }
}
