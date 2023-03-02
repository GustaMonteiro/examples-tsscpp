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
        root["TPMVersion"] = 2;
        root["EKpub"] = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAthSyFeVj8dWdDmJBfYP8ElsPfSna5zR7nDADTuqREKL5KTUAIZmw7JGsC19YP1K/m50M1NMTAyyIeqctTy1vn94vehBrSEotbIVyj/Z45rVDhCcx0Jn4EkjopaoM7xMgt9R/NOCyX8gXLU+F6Afr6lc7R9ob3MIOR+1z7QvnXSN+hMvh9m5dBBYTI+UsJ5w1+z+X69VQu0fGe4c2yL6Vw6SLY6/2lxGKpGTWdoFm+Nn/XojGqTOhPZiQ99T12InlWLkppH5bMVzLUIshaRJPN8rOnMwdkVuChOsNJ+eHExX8TcivIhBMHG1yTRABKEC+serDK/p4f047+XttwDcNNwIDAQAB";
        akParameters["Public"] = "AAEACwAFBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAFAAECAAAAAAAAQDrrr22jWa5ySy/rno3WMLG05KewCGj4jN0Y8pK2+83V4qiqpOBSIKmlsnKneUM2uFaWhhGlapvXWAD3KGVOZ9NYU2q2+uHDXV6IkPVgVo/S4qN9+2+l/erp7FwDrRLgEomoIzNdgWnVYn+NVQxJXTHTvQrw2fVeYSpsu9+feQ3oaYTCDf+RW7g7x0E84rdXig86s5cs6xtXijEUZtm4dhZBaw1lP0r0SLRD2MtQep5RpDlLOHaCp9ghneM4XK6I/oRonRMo1jvyYWyg8vAmmndCrH4x6TViWiVdUKqo7+ptS/r6mqUKEShJ9umrO2GIBIS3Zyx49PcKkKRxfsmWuUJ";
        akParameters["UseTCSDActivationFormat"] = false;
        akParameters["CreateData"] = "AAAAAAAg47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFUBAAsAIgALOyDqlR1A7yIRtJUe4a8rxHtxVJItEjRTilRv/M5DzkYAIgAL2wSQnCKgLL1TGKUreXra2BFHEkr5koxLbxud+2xQuvsAAA==";
        akParameters["CreateAttestation"] = "/1RDR4AaACIAC0/Ii5jg4zsvxVlMA2EhIMgtmeacFlfseS/pO+dCwez7AAAAAAACOnBH7HHpWtdLb0IaAb6Z3ehFCJZRACIAC4sH8uLNoGTQavVwmFQjS1dfff/D13bXfJef2B8BmW0mACB9xuiDscZkcaz2KUoBUhQBNi4ijSBI04jKkUlZNyd9Aw==";
        akParameters["CreateSignature"] = "ABQABAEAgCDlvMh6fzsKbTE97gWWZ3VIyflMSkbzyADlu30lXqfzYfi/nDji5XSFwW2lDUXB+3L4sshhfFtjxRdPpEcGUEgp/3oyI+WkraNaT+p7Xv7TIcGWBVqEadB4K0f+DxLnHGkc91PeugBppEZ6DNpL73uQ6+EeNSVJOOTNwpduInqeE30DzHwwCa6Ist8gU4RIfQHzWsHqKl/d5rXp4Rm5wAB6s54k9rxi3z0s3x+cEb9xuL4KyoXK2mPJgFACUgo0cDwRRtzB0gY8M+W73tXdnkA5MdJGHsOfipYzqNiVQZoJxJR0wk0/BORQvYU7d/LI3BXc1vwWSobrbqLgZEt/HA==";

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

    return 0;
}