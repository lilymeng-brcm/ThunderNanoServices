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

#include <WPEFramework/plugins/Request.h>
#include <WPEFramework/protocols/WebLink.h>
#include <websocket/WebTransfer.h>

namespace WPEFramework {
namespace {

    class Challenger {

    private:
        static void process_challenge_callback(struct OpenCDMSession* session, void* userData, const char url[], const uint8_t challenge[], const uint16_t challengeLength)
        {
            Challenger* comm = reinterpret_cast<Challenger*>(userData);
            comm->ProcessChallengeCallback(url, challenge, challengeLength);
        }

        static void key_update_callback(struct OpenCDMSession* session, void* userData, const uint8_t keyId[], const uint8_t length)
        {
            Challenger* comm = reinterpret_cast<Challenger*>(userData);
            comm->KeyUpdateCallback();
        }

        static void error_message_callback(struct OpenCDMSession* session, void* userData, const char message[])
        {
            Challenger* comm = reinterpret_cast<Challenger*>(userData);
            comm->ErrorMessageCallback();
        }

        static void keys_updated_callback(const struct OpenCDMSession* session, void* userData)
        {
            Challenger* comm = reinterpret_cast<Challenger*>(userData);
            comm->KeysUpdatedCallback();
        }

        void ProcessChallengeCallback(const char url[], const uint8_t challenge[], const uint16_t challengeLength)
        {
            TRACE_L1("Processing challenge to url: %s", url);
            _server.Exchange(url, challenge, challengeLength);
        }

        void KeyUpdateCallback()
        {
            TRACE_L1("Key Update Callback called");
        }

        void ErrorMessageCallback()
        {
            TRACE_L1("Error Message Callback called");
        }

        void KeysUpdatedCallback()
        {
            TRACE_L1("Keys Updated Callback called");
        }

    private:
        class LicenseServerLink : public Web::WebLinkType<Core::SocketStream, Web::Response, Web::Request, Challenger&> {

            using WebLinkClass = Web::WebLinkType<Core::SocketStream, Web::Response, Web::Request, Challenger&>;

        public:
            LicenseServerLink() = delete;
            LicenseServerLink(const LicenseServerLink& copy) = delete;
            LicenseServerLink& operator=(const LicenseServerLink&) = delete;

            LicenseServerLink(Challenger& parent)
                : WebLinkClass(2, parent, false, Core::NodeId(), Core::NodeId(), 2048, 2048)
                , _challengeRequest(Core::ProxyType<Web::Request>::Create())
                , _bodyRequest(Core::ProxyType<Web::TextBody>::Create())
                , _bodyResponse(Core::ProxyType<Web::TextBody>::Create())
                , _waitForEvent(false, true)
            {
                _challengeRequest->Verb = Web::Request::HTTP_POST;
                _challengeRequest->Connection = Web::Request::CONNECTION_CLOSE;
            }

            ~LicenseServerLink() override
            {
                Close(Core::infinite);
            }

            void Exchange(string rawUrl, const uint8_t challenge[], const uint16_t challengeLength)
            {
                Core::URL url(rawUrl);
                _challengeRequest->Path = '/' + url.Path().Value();
                _challengeRequest->Host = url.Host().Value();

                Core::NodeId remoteNode(url.Host().Value().c_str(), 80, Core::NodeId::TYPE_IPV4);
                if (remoteNode.IsValid() == false) {
                    TRACE_L1("Connection to %s unavailable", rawUrl.c_str());
                } else {

                    InitializeBody(challenge, challengeLength);

                    Link().RemoteNode(remoteNode);
                    Link().LocalNode(remoteNode.AnyInterface());
                    uint32_t result = Open(0);

                    if (_waitForEvent.Lock(3000) != Core::ERROR_NONE) {
                        TRACE_L1("Unhandled error while sending challenge request: %d", result);
                    }
                }
            }

        private:
            /* TODO:
            *   It looks like the challenge data coming over from OCDM has this: ':Type:' prefix.
            *   Why is this supposed to be ommited when sending the challenge request ?
            *   And more importantly, why should it be done in the challenge handler ?
            */

            void InitializeBody(const uint8_t challenge[], const uint16_t challengeLength)
            {
                string body(reinterpret_cast<const char*>(challenge), challengeLength);

                size_t index = body.find(":Type:");
                size_t offset = 0;

                if (index != std::string::npos) 
                    offset = index + strlen(":Type:");

                _bodyRequest->assign(body, offset, body.length() - offset);
                _challengeRequest->Body<Web::TextBody>(_bodyRequest);
                _challengeRequest->ContentType = Web::MIMETypes::MIME_TEXT_XML;
            }

            // Web::WebLinkType methods
            // --------------------------------------
            void LinkBody(Core::ProxyType<Web::Response>& element) override
            {
                // Send an event if the response is partially wrong
                element->Body<Web::TextBody>(_bodyResponse);
            }

            void Received(Core::ProxyType<Web::Response>& response) override
            {
                std::string s;
                response->ToString(s);
                _waitForEvent.SetEvent();
                TRACE_L1("Received challenge response \n\n%s\n\n", s.c_str());
            }

            void Send(const Core::ProxyType<Web::Request>& request) override
            {
                TRACE_L1("Sending request");
                ASSERT(request == _challengeRequest);
            }

            void StateChange() override
            {
                if (IsOpen()) {
                    Submit(_challengeRequest);
                }
            }

        private:
            mutable Core::CriticalSection _adminLock;
            Core::ProxyType<Web::Request> _challengeRequest;
            Core::ProxyType<Web::TextBody> _bodyRequest;
            Core::ProxyType<Web::TextBody> _bodyResponse;
            Core::Event _waitForEvent;
        };

    public:
        Challenger()
            : _server(*this)
            , _callbacks{ process_challenge_callback, key_update_callback, error_message_callback, keys_updated_callback }
        {
        }

        Core::ProxyType<Web::Response> Element()
        {
            return (PluginHost::Factories::Instance().Response());
        }

        OpenCDMSessionCallbacks& OcdmCallbacks()
        {
            return _callbacks;
        }

    private:
        OpenCDMSessionCallbacks _callbacks;
        LicenseServerLink _server;
    };
}
}