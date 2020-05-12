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

#include "IExchange.h"

namespace WPEFramework {
namespace CENCDecryptor {

    class Exchanger : public IExchange, public Core::Thread {
    public:
        Exchanger(const std::string& url);
        Exchanger() = delete;
        Exchanger(const Exchanger&) = delete;
        Exchanger& operator=(const Exchanger&) = delete;

        // IExchange methods
        // --------------------------------------------------------------------
        uint32_t Submit(Core::ProxyType<Web::Request>,
            Core::ProxyType<IExchange::ICallback>, uint32_t waitTime) override;

        uint32_t Revoke(Core::ProxyType<IExchange::ICallback>) override;

        // Core::Thread method
        // ------------------------
        uint32_t Worker() override;

        Core::ProxyType<Web::Response> Element();

    private:
        class Challenger : public Web::WebLinkType<Core::SocketStream, Web::Response, Web::Request, Exchanger&> {
            using WebLinkClass = Web::WebLinkType<Core::SocketStream, Web::Response, Web::Request, Exchanger&>;

        public:
            Challenger() = delete;
            explicit Challenger(Exchanger& parent, Core::Event& resReceived);

            void Exchange(const Core::ProxyType<Web::Request>&);
            Core::ProxyType<Web::Response> Response();

        private:
            void LinkBody(Core::ProxyType<Web::Response>& element) override;
            void Received(Core::ProxyType<Web::Response>& text) override;
            void Send(const Core::ProxyType<Web::Request>& text) override;
            void StateChange() override;

            Core::Event& _resReceived;
            Core::ProxyType<Web::Response> _response;
            Core::ProxyType<Web::TextBody> _responseBody;
        };

        struct LicenseRequestData {
            Core::ProxyType<Web::Request> licenseRequest;
            Core::ProxyType<IExchange::ICallback> licenseHandler;
            uint32_t timeout;

            bool operator==(const LicenseRequestData& a) const
            {
                return (this->licenseHandler == a.licenseHandler);
            }
        };

        std::string _url;
        Core::QueueType<LicenseRequestData> _queue;
        Core::Event _resReceived;
        Challenger _challenger;
    };
}
}
//
