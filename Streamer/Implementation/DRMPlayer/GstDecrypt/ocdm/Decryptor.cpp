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

#include "Decryptor.hpp"

#include <gst/gstbuffer.h>
#include <gst/gstevent.h>
#include <gst/gstprotection.h>

namespace WPEFramework {
namespace CENCDecryptor {

    OCDMDecryptor::OCDMDecryptor()
        : _keySystems()
        , _system(nullptr)
        , _session(nullptr)
        , _exchanger()
        , _factory()
        , _callbacks({ process_challenge_callback,
              key_update_callback,
              error_message_callback,
              keys_updated_callback })
    {
    }

    gboolean OCDMDecryptor::Initialize(Core::ProxyType<IKeySystems> keySystems,
        Core::ProxyType<IExchangeFactory> factory)
    {
        if (keySystems == nullptr || keySystems->Get()->Count() == 0) {
            TRACE_L1("Cannot decrypt with no supported keysystems.");
            return FALSE;
        } else {
            auto keySystemsIt = keySystems->Get();
            std::string keysystem;
            while (keySystemsIt->Next(keysystem)){
                _keySystems.push_back(keysystem);
            }
            _factory = factory;
            return TRUE;
        }
    }

    gboolean OCDMDecryptor::HandleProtection(GstEvent* event)
    {
        CENCSystemMetadata metadata;
        ParseProtectionEvent(metadata, *event);
        _system = opencdm_create_system(metadata.keySystem.c_str());
        if (_system != nullptr) {

            BufferView dataView(metadata.initData, GST_MAP_READ);

            OpenCDMError result = opencdm_construct_session(_system,
                LicenseType::Temporary,
                "cenc",
                dataView.Raw(),
                static_cast<uint16_t>(dataView.Size()),
                nullptr,
                0,
                &_callbacks,
                this,
                &_session);
        }
        return TRUE; //TODO
    }

    GstFlowReturn OCDMDecryptor::Decrypt(GstBuffer* buffer)
    {
        return GST_FLOW_OK;
    }

    void OCDMDecryptor::ParseProtectionEvent(CENCSystemMetadata& metadata, GstEvent& event)
    {
        const char* systemId = nullptr;
        const char* origin = nullptr;
        GstBuffer* data = nullptr;

        gst_event_parse_protection(&event, &systemId, &data, &origin);
        metadata.keySystem.assign(systemId);
        metadata.origin.assign(origin);
        metadata.initData = data;
    }

    void OCDMDecryptor::ParseDecryptionData(DecryptionMetadata&)
    {
    }

    Core::ProxyType<Web::Request> OCDMDecryptor::PrepareChallenge(const string& challenge)
    {
        size_t index = challenge.find(":Type:");
        size_t offset = 0;

        if (index != std::string::npos)
            offset = index + strlen(":Type:");

        Core::ProxyType<Web::Request> request;
        Core::ProxyType<Web::TextBody> requestBody;
        requestBody->assign(challenge.substr(offset));
        request->Body<Web::TextBody>(requestBody);

        return request;
    }
}
}