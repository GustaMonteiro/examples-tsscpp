// test-requests-cpp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include <string>
#include <sstream>
#include <iostream>

#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>

#include <json/json.h>
#include <memory>

int main(int, char**)
{
    try {


        Json::FastWriter writer;
        Json::Value root;
        Json::Value akParameters;
        root["ID"] = "2";
        root["TPMVersion"] = "2";
        root["EKpub"] = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2FuIS+QMG8dyOTQ9kadzInTymMnmafXNAPAq37WjpH/essTDn+k4vTfW/QMs+8xs+2pe3GMgmKWBybcmUzAL/NueCRxCF4LuJHYyqYTjxK+zxRkZT6ZqMopyChTZ0qSp/EYYdd+9YB56vryQ2iBnJbxg7PSjMl6kAcvzjYK85U/sVAS6V+k+DruMu2gdB5rQgxg470tuPRN8tE+N6XHCUPPf5EqF9eLmBObvRuwr+FUKcEMqjOkBJPGJFoMypMs5vJzj40gtm14lNDn3B3rzsZ4Ww2DSHF1HTLRnKBbkM24gE2x9SFpK/yGbIH9H0xp+FbGvFg3/oZ0APcpH7sJz6wIDAQAB";
        akParameters["Public"] = "AAEACwAFBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAFAAECAAAAAAAAQChh2H07bgAmP8JGxdqG0qQxilZu3m0HaHOv9VmNznb1phyZhMkwPUExPwMaaEEIdRpshtc/tRdKXElp3omSCCSNaE6JbjNLvLxiGKVotSB6zAB6ZvL4WuDJjtQqD1NKzpvOtpLYmqg1MwV3PYEYDLpU/MjEYA9abNXjnuqUtM0p6lUnsBRKRKxnUgwsMTpzF8mDjPzFeEwVmdSQwsFOdqTxZHAisZEicCVO3kpU13yybR7wyUzVPoGoIM0GSMezQsI9jCYlqzmCf6T1mTmwBmzXN8Pbz2S56bTxjiCnM13uIljuP90TJPSZuq/YCuNGFffF3YZHfwwLpCM8uy8Lxpn";
        akParameters["UseTCSDActivationFormat"] = "false";
        akParameters["CreateData"] = "AAAAAAAg47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFUBAAsAIgALJhjDCmNrglM43Tq2ygzrMYalA2AQ4c54TQkzJnQKpkQAIgALOxuOMGNb/ZGcB6mDOBv63kDHssbCY5HrDWqlw6E7FtwAAA==";
        akParameters["CreateAttestation"] = "/1RDR4AaACIAC/6XT2Vmijo9KCOUp2h3xNOcmwWmdWwB3UE2Dj9Cj8IoAAAAAAACj61kUEwQvHAooHuHAWaOtmbh1ELoACIACwyF5bHZ05fFF0VYOA4fFX9xXX92ajKvtsTxjaXxRBJwACBZFibRNyqUH1y3B5tGxp/zQhVuu1o8dR5oEXkV3r5vpA==";
        akParameters["CreateSignature"] = "ABQABAEAcG48uD9hinoEn1plN/VO2nRqxM4nzc+dLp7KOuitMbfd/8JaluBJqy/6AyKSqKdcAwzGFs/r8UrLoiC8P0cVTWoxXWl4VA5R4fgaK+lbb4OLOUQ2HMJpMgUS0QsveSc6yAQ4QUe3trz1BwuQuhZMiRXNwtp73ffzY1jHos+ASVA2wZJRXjuEiMTdCQwJ6oZDSPXtnAa2aq/1LKPJfQmk6buYMhdFTM2VuqAVIy/yW8HaBsAqp8gwsqnkitA/fFSWe2ehy4YLzsFMdesrovHr/Kc1wD773DYRglCujk13lsFEtTMb6QPDtITqoL9Rr3rR/4svPTltP2uTkZnqbeRBeg==";

        root["AK"] = akParameters;

        std::string sendData = writer.write(root);

        std::cout << sendData << std::endl;

        curlpp::Cleanup cleaner;
        curlpp::Easy request;

        std::ostringstream response;

        // Set the writer callback to enable cURL 
        // to write result in a memory area
        request.setOpt(new curlpp::options::WriteStream(&response));

        // Setting the URL to retrive.
        request.setOpt(new curlpp::options::Url("http://localhost:8080/initialChallenge"));

        std::list<std::string> header;
        header.push_back("Content-Type: application/octet-stream");

        request.setOpt(new curlpp::options::HttpHeader(header));

        request.setOpt(new curlpp::options::PostFields(sendData));
        request.setOpt(new curlpp::options::PostFieldSize(sendData.size()));

        request.perform();

        std::cout << "Response from server:" << std::endl;
        std::cout << response.str() << std::endl;

        return EXIT_SUCCESS;
    }
    catch (curlpp::LogicError& e) {
        std::cout << e.what() << std::endl;
    }
    catch (curlpp::RuntimeError& e) {
        std::cout << e.what() << std::endl;
    }

	return 0;
}