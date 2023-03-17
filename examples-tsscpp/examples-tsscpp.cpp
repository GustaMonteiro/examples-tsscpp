// examples-tsscpp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
//
#include <iostream>
#include <Tpm2.h>
#include <TpmDevice.h>
#include <TpmTypes.h>

#include <openssl/bio.h>

#include <botan/botan.h>
#include <botan/rsa.h>

#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>

#include <json/json.h>
#include <memory>

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
        vector<TPMS_PCR_SELECTION> pcrToRead{ TPMS_PCR_SELECTION(TPM_ALG_ID::SHA256, pcrIndex) };

        pcrVal = tpm.PCR_Read(pcrToRead);
    }
    else {
        vector<UINT32> pcrIndexes = { 0, 1, 2, 3, 4 };

        for (UINT32 pcr : pcrIndexes) {
            tpm.PCR_Event(pcr, tpm.GetRandom(5));
        }

        vector<TPMS_PCR_SELECTION> pcrToRead{ TPMS_PCR_SELECTION(TPM_ALG_ID::SHA256, pcrIndexes) };

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
    AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::HMAC, TPM_ALG_ID::SHA256);

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
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA256,
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
CreateResponse MakeChildSigningKey(TPM_HANDLE parent, bool restricted)
{
    TPMA_OBJECT restrictedAttribute = TPMA_OBJECT::restricted;

    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth | restrictedAttribute,
        {},  // No policy
        TPMS_RSA_PARMS({}, TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 2048, 65537), // PKCS1.5
        TPM2B_PUBLIC_KEY_RSA());

    return tpm.Create(parent, {}, templ, {}, {});

    
    //return tpm.Load(parent, newSigningKey.outPrivate, newSigningKey.outPublic);
}
TpmCpp::CreatePrimaryResponse MakeEndorsementKey()
{
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        {},           // No policy
        TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
    // Create the key
    return tpm.CreatePrimary(TPM_RH::ENDORSEMENT, {}, storagePrimaryTemplate, {}, {});
}

void RsaEncryptDecrypt()
{
    
    // This sample demostrates the use of the TPM for RSA operations.

    // We will make a key in the "{} hierarchy".
    TPMT_PUBLIC primTempl(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin,
        {},  // No policy
        TPMS_RSA_PARMS({}, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA256), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());

    // Create the key
    auto storagePrimary = tpm.CreatePrimary(TPM_RH_NULL, {}, primTempl, {}, {});

    TPM_HANDLE& keyHandle = storagePrimary.handle;

    ByteVec dataToEncrypt = TPM_HASH::FromHashOfString(TPM_ALG_ID::SHA256, "secret");
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
    vector<TPM_ALG_ID> hashAlgs = { TPM_ALG_ID::SHA256, TPM_ALG_ID::SHA256 };
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
    auto initPcr = tpm.PCR_Read({ {TPM_ALG_ID::SHA256, 0} });
    auto hashVal2 = tpm.EventSequenceComplete(TPM_HANDLE::Pcr(0), hashHandle, data1);
    auto expected = Crypto::Hash(TPM_ALG_ID::SHA256, accumulator);
    auto finalPcr = tpm.PCR_Read({ {TPM_ALG_ID::SHA256, 0} });

    // Is this what we expect?
    TPM_HASH expectedPcr(TPM_ALG_ID::SHA256, initPcr.pcrValues[0]);
    expectedPcr.Extend(expected);

    if (expectedPcr == finalPcr.pcrValues[0])
        cout << "EventSequenceComplete gives expected answer:  " << endl << expectedPcr.ToString(false) << endl;
    _ASSERT(expectedPcr == finalPcr.pcrValues[0]);
} // Hash()

void PrimaryKeys()
{
    // To create a primary key the TPM must be provided with a template.
    // This is for an RSA1024 signing key.
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
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
    vector<BYTE> NullVec;
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign |
        TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM |
        TPMA_OBJECT::sensitiveDataOrigin |
        TPMA_OBJECT::userWithAuth,
        NullVec,
        TPMS_RSA_PARMS(
            TPMT_SYM_DEF_OBJECT(),
            TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 1024, 65537),
        TPM2B_PUBLIC_KEY_RSA(NullVec));

    // Set the use-auth for the key. Note the second parameter is NULL
    // because we are asking the TPM to create a new key.
    ByteVec userAuth = ByteVec{ 1, 2, 3, 4 };
    TPMS_SENSITIVE_CREATE sensCreate(userAuth, NullVec);

    // We don't need to know the PCR-state with the key was created so set this
    // parameter to a {}-vector.
    vector<TPMS_PCR_SELECTION> pcrSelect{};

    // Ask the TPM to create the key
    CreatePrimaryResponse newPrimary = tpm.CreatePrimary(tpm._AdminOwner, sensCreate, templ, NullVec, pcrSelect);

    // Print out the public data for the new key. Note the "false" parameter to
    // ToString() "pretty-prints" the byte-arrays.
    cout << "New RSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;

    // Sign something with the new key. First set the auth-value in the handle.
    TPM_HANDLE& signKey = newPrimary.handle;
    signKey.SetAuth(userAuth);

    TPMT_HA dataToSign = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA256, "abc");

    auto sig = tpm.Sign(signKey,
        dataToSign.digest,
        TPMS_NULL_SIG_SCHEME(),
        TPMT_TK_HASHCHECK());

    cout << "Signature:" << endl << sig->ToString(false) << endl;

    // Use TSS.C++ to validate the signature
    bool sigOk = newPrimary.outPublic.ValidateSignature(dataToSign, *sig);
    cout << "Signature is " << (sigOk ? "OK" : "BAD") << endl;
    _ASSERT(sigOk);

    tpm.FlushContext(newPrimary.handle);
} // SigningPrimary()

std::string getEkPublicPem(TpmCpp::CreatePrimaryResponse ek) {
    auto mod = ek.outPublic.unique->toBytes();
    auto rsaPublicKey = Botan::RSA_PublicKey(Botan::BigInt(mod.data(), mod.size()), 65537);
    auto pemFormatKey = Botan::X509::PEM_encode(rsaPublicKey);
    std::cout << pemFormatKey << std::endl;
    
    pemFormatKey.erase(std::remove(pemFormatKey.begin(), pemFormatKey.end(), '\n'), pemFormatKey.cend());

    return pemFormatKey.substr(26, pemFormatKey.size() - 50);
} // getEkPublicPem()

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <string>

std::string base64_encode(const ByteVec input) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string output(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);

    return output;
}

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
    //SigningPrimary(); // working
    
    auto ek = MakeEndorsementKey();  
    //std::cout << getEkPublicPem(ek) << endl << std::endl;

    TPM_HANDLE ekHandle = ek.handle;

    TPMT_PUBLIC akTemplate(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::restricted,
        {},  // No policy
        TPMS_RSA_PARMS({}, TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());

    // Ask the TPM to create the key. For simplicity we will leave the other parameters
    // (apart from the template) the same as for the storage key.
    auto ak = tpm.Create(ekHandle, {}, akTemplate, {}, {});

    TPM_HANDLE akHandle = tpm.Load(ekHandle, ak.outPrivate, ak.outPublic);

    ByteVec nonce{ 5, 6, 7 };
    auto certify = tpm.CertifyCreation(akHandle, akHandle, nonce, ak.creationHash,
        TPMS_NULL_SIG_SCHEME(), ak.creationTicket);

    cout << certify.ToString() << endl << endl;

    auto ekPubContent = getEkPublicPem(ek);

    auto publicContent = base64_encode(ak.outPublic.toBytes());
    publicContent.erase(std::remove(publicContent.begin(), publicContent.end(), '\n'), publicContent.cend());

    cout << publicContent << endl << endl;

    auto createDataContent = base64_encode(ak.creationData.toBytes());
    createDataContent.erase(std::remove(createDataContent.begin(), createDataContent.end(), '\n'), createDataContent.cend());

    cout << createDataContent << endl << endl;

    auto createAttestationContent = base64_encode(certify.certifyInfo.toBytes());
    createAttestationContent.erase(std::remove(createAttestationContent.begin(), createAttestationContent.end(), '\n'), createAttestationContent.cend());

    cout << createAttestationContent << endl << endl;

    ByteVec fullSignatureContent;
    auto signatureAlgorithm = certify.signatureSigAlg();
    fullSignatureContent.push_back(signatureAlgorithm >> 8);
    fullSignatureContent.push_back(signatureAlgorithm & 0xff);
    for (int i = 0; i < certify.signature->toBytes().size(); i++) {
        fullSignatureContent.push_back(certify.signature->toBytes()[i]);
    }

    auto createSignatureContent = base64_encode(fullSignatureContent);
    createSignatureContent.erase(std::remove(createSignatureContent.begin(), createSignatureContent.end(), '\n'), createSignatureContent.cend());

    cout << createSignatureContent << endl << endl;

    try {
        Json::FastWriter jsonWriter;
        Json::Value jsonRoot;
        Json::Value jsonAttestationParameters;
        //root["ID"] = "30";
        //root["TPMVersion"] = 2;
        //root["EKpub"] = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2FuIS+QMG8dyOTQ9kadzInTymMnmafXNAPAq37WjpH/essTDn+k4vTfW/QMs+8xs+2pe3GMgmKWBybcmUzAL/NueCRxCF4LuJHYyqYTjxK+zxRkZT6ZqMopyChTZ0qSp/EYYdd+9YB56vryQ2iBnJbxg7PSjMl6kAcvzjYK85U/sVAS6V+k+DruMu2gdB5rQgxg470tuPRN8tE+N6XHCUPPf5EqF9eLmBObvRuwr+FUKcEMqjOkBJPGJFoMypMs5vJzj40gtm14lNDn3B3rzsZ4Ww2DSHF1HTLRnKBbkM24gE2x9SFpK/yGbIH9H0xp+FbGvFg3/oZ0APcpH7sJz6wIDAQAB";
        //akParameters["Public"] = "AAEACwAFBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAFAAECAAAAAAAAQC9rmpxiytl2DgwlohkQbGTJ8tvUBRPIL37yhqYnh/fk86qdOFwr8PkZFIicMXt+bWXFDw55GRckfaMAvtNU9+Cnt+/4M8FAdmKT2vw7x9Dh94/VhCnWbJIqkP/mrlOKGS+MY5hBOBFa4bjOIuIPlX3sEb5C0HDnwbJf6wVYOw+gHgOC39vxxIGiqkgrK7YmahcWf3pof6C55I7kiGbr3E4vzcwGQNIMbGDewoO77RY5yb3M7vJRmJTbVbXx4U12lZCxCk4IddqOYUvp+xlx6WeoyyyuyUc8i1Gc3dMbUGf0DTjJKLd27G9uCb9MQWbcvBxS1ICc1kaA/gxR8zC3cqb";
        //akParameters["UseTCSDActivationFormat"] = false;
        //akParameters["CreateData"] = "AAAAAAAg47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFUBAAsAIgALOyDqlR1A7yIRtJUe4a8rxHtxVJItEjRTilRv/M5DzkYAIgAL2wSQnCKgLL1TGKUreXra2BFHEkr5koxLbxud+2xQuvsAAA==";
        //akParameters["CreateAttestation"] = "/1RDR4AaACIAC4R3fzhZJN2pKoO1d7P8IbshfdUXz9+xccZxmRmiyHoeAAAAAAACSPaE7AbYzWWe4Ms+ASQgsS94JzAEACIAC/WcfhxfIDZ83PTSHI6hd53xMiuxNAId589Un8PEc6FsACB9xuiDscZkcaz2KUoBUhQBNi4ijSBI04jKkUlZNyd9Aw==";
        //akParameters["CreateSignature"] = "ABQABAEAq6WAkqJbA+YLtFJ80rJOYN6evWh2poC+/NIb7hebhTLffbpuKGaWnBtaxPs1qM6rtGyf5XJs1MKmqPIuJ7FZGqK1pnDofrbC5XWoV3Bzyl0uwM1rSLkL96VyCTU/v5QBA+CANqIKAQQ1iTNulE0yY63Lpe6A4s9cYf9XHpKEbYs6fr2q7QxASaJA+lsLkCvVih9Gw9eBrCqmoPkfpVr3Aw613NqEB44LGj3og0wOAjtHlXN0rt/cKTR85y1kaOKjoXPIHuIO7NEonioQ5FOomPJt7hodov5ozu32ZIkxxGMoVnOiQDZgC3Zml631YfBlUuQati81W2tFp9CUlZ6V+g==";

        jsonRoot["ID"] = "30";
        jsonRoot["TPMVersion"] = 2;
        jsonRoot["EKpub"] = ekPubContent;
        jsonAttestationParameters["Public"] = publicContent;
        jsonAttestationParameters["UseTCSDActivationFormat"] = false;
        jsonAttestationParameters["CreateData"] = createDataContent;
        jsonAttestationParameters["CreateAttestation"] = createAttestationContent;
        jsonAttestationParameters["CreateSignature"] = createSignatureContent;

        jsonRoot["AK"] = jsonAttestationParameters;

        std::string sendData = jsonWriter.write(jsonRoot);

        std::cout << sendData << std::endl;

        curlpp::Cleanup cleaner;
        curlpp::Easy request;

        std::ostringstream response;

        // Set the writer callback to enable cURL 
        // to write result in a memory area
        request.setOpt(new curlpp::options::WriteStream(&response));

        // Setting the URL to retrive.
        request.setOpt(new curlpp::options::Url("http://localhost:8080/initialChallenge"));

        //std::list<std::string> header;
        //header.push_back("Content-Type: application/octet-stream");

        //request.setOpt(new curlpp::options::HttpHeader(header));

        request.setOpt(new curlpp::options::PostFields(sendData));
        request.setOpt(new curlpp::options::PostFieldSize(sendData.size()));

        request.perform();

        std::cout << "Response from server:" << std::endl;
        std::cout << response.str() << std::endl;

        Json::Reader reader;

        Json::Value responseJson;

        reader.parse(response.str(), responseJson);

        std::cout << "Credential: " << responseJson["Encrypted Credential"]["Credential"].asString() << std::endl;
        std::cout << "Secret: " << responseJson["Encrypted Credential"]["Secret"].asString() << std::endl;

        return EXIT_SUCCESS;
    }
    catch (curlpp::LogicError& e) {
        std::cout << e.what() << std::endl;
    }
    catch (curlpp::RuntimeError& e) {
        std::cout << e.what() << std::endl;
    }

    /*
    std::string filtered = pemFormatKey.substr(27, pemFormatKey.size() - 53);

    filtered.erase(std::remove(filtered.begin(), filtered.end(), '\n'), filtered.cend());
    cout << filtered << endl;

    
    cout << filtered << endl;*/

    //std::cout << pemFormatKey.substr(26, pemFormatKey.size() - 26) << std::endl;


   

    //{
        //TpmCpp::CreatePrimaryResponse keyResponse = MakeEndorsementKey();

        //cout << keyResponse.Serialize(SerializationType::JSON) << endl;

        //auto unique = keyResponse.outPublic.unique;

        //cout << unique->toBytes() << endl;
    //}


    //TPM_HANDLE ekHandle = MakeEndorsementKey();
    //cout << ekHandle.handle << endl;


    if (useSimulator) {
        ShutdownTpmSimulator();
    }
}
