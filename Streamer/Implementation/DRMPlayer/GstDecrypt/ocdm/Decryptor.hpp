/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "GstBufferView.hpp"
#include "IExchangeFactory.hpp"
#include "IGstDecryptor.hpp"
#include "ResponseCallback.hpp"
#include <ocdm/open_cdm.h>

namespace WPEFramework {
namespace CENCDecryptor {
    class OCDMDecryptor : public IGstDecryptor {
    public:
        OCDMDecryptor();
        OCDMDecryptor(const OCDMDecryptor&) = delete;
        OCDMDecryptor& operator=(const OCDMDecryptor&) = delete;

        gboolean Initialize(Core::ProxyType<IKeySystems>,
            Core::ProxyType<IExchangeFactory>) override;
        
        gboolean HandleProtection(GstEvent*) override;
        GstFlowReturn Decrypt(GstBuffer*) override;

    private:
        struct DecryptionMetadata {
            GstBuffer* subSample;
            uint32_t subSampleCount;
            GstBuffer* IV;
            GstBuffer* keyID;
        };

        struct CENCSystemMetadata {
            std::string keySystem;
            std::string origin;
            GstBuffer* initData;

            bool CheckIntegrity() { return !keySystem.empty() && !origin.empty() && initData != nullptr; }
        };

        void ParseProtectionEvent(CENCSystemMetadata& metadata, GstEvent& event);
        void ParseDecryptionData(DecryptionMetadata&);

        std::vector<std::string> _keySystems;
        OpenCDMSystem* _system;
        OpenCDMSession* _session;
        Core::ProxyType<IExchange> _exchanger;
        Core::ProxyType<IExchangeFactory> _factory;
        OpenCDMSessionCallbacks _callbacks;

    private:
        Core::ProxyType<Web::Request> PrepareChallenge(const string& challenge);

        // Callbacks used for wrapping the OpenCDM C-API.
        // ------------------------------------------------------------------------------
        static void process_challenge_callback(OpenCDMSession* session,
            void* userData,
            const char url[],
            const uint8_t challenge[],
            const uint16_t challengeLength)
        {
            OCDMDecryptor* comm = reinterpret_cast<OCDMDecryptor*>(userData);
            string challengeData(reinterpret_cast<const char*>(challenge), challengeLength);
            comm->ProcessChallengeCallback(session, url, challengeData);
        }

        static void key_update_callback(OpenCDMSession* session,
            void* userData,
            const uint8_t keyId[],
            const uint8_t length)
        {
            OCDMDecryptor* comm = reinterpret_cast<OCDMDecryptor*>(userData);
            comm->KeyUpdateCallback(session, userData, keyId, length);
        }

        static void error_message_callback(OpenCDMSession* session,
            void* userData,
            const char message[])
        {
            OCDMDecryptor* comm = reinterpret_cast<OCDMDecryptor*>(userData);
            comm->ErrorMessageCallback();
        }

        static void keys_updated_callback(const OpenCDMSession* session, void* userData)
        {
            OCDMDecryptor* comm = reinterpret_cast<OCDMDecryptor*>(userData);
            comm->KeysUpdatedCallback();
        }

        void ProcessChallengeCallback(OpenCDMSession* session,
            const string& url,
            const string& challenge)
        {
            TRACE_L1("Processing challenge to url: %s", url.c_str());

            Core::ProxyType<IExchange::ICallback> callback(*(new OCDMResponseCallback(_session)));
            Core::ProxyType<IExchange> exchange(_factory->Create(url));
            exchange->Submit(PrepareChallenge(challenge), callback, 4000);
        }

        void KeyUpdateCallback(OpenCDMSession* session,
            void* userData,
            const uint8_t keyId[],
            const uint8_t length)
        {
        }

        void ErrorMessageCallback()
        {
            TRACE_L1("Error Message Callback called");
        }

        void KeysUpdatedCallback()
        {
            TRACE_L1("Keys Updated Callback called");
        }
    };
}
}
