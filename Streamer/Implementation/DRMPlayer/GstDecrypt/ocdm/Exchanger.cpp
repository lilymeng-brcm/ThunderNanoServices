#include "Exchanger.hpp"
#include <plugins/System.h>

namespace WPEFramework {
namespace CENCDecryptor {

    Exchanger::Exchanger(const std::string& url)
        : _url(url)
        , _queue(10)
        , _resReceived(false, true)
        , _challenger(*this, _resReceived)
    {
    }

    Core::ProxyType<Web::Response> Exchanger::Element()
    {
        return (PluginHost::IFactories::Instance().Response());
    }

    uint32_t Exchanger::Worker()
    {
        LicenseRequestData licenseData;
        _queue.Extract(licenseData, Core::infinite);

        _challenger.Exchange(licenseData.licenseRequest);

        // TODO: vague error codes
        if (_resReceived.Lock(4000) != Core::ERROR_NONE) {
            TRACE_L1("Unhandled error while sending challenge request");
            return Core::ERROR_GENERAL;
        } else {
            licenseData.licenseHandler->Response(licenseData.licenseRequest,
                _challenger.Response());
            return Core::ERROR_NONE;
        }
    }

    uint32_t Exchanger::Submit(Core::ProxyType<Web::Request> request,
        Core::ProxyType<IExchange::ICallback> onResponse, uint32_t waitTime)
    {
        // TODO: Handle waitTime
        // This isn't as straightforward, because there are two wait times to consider.
        //  - time spent waiting for queue insertion
        //  - time spent waiting for a server response
        // For the interface perspective, a request should be auto-revoked
        // if some wait time has elapsed.
        bool result = _queue.Post(LicenseRequestData({ request, onResponse, waitTime }));
        // TODO: Something a bit more descriptive than ERROR_GENERAL?
        return result ? Core::ERROR_GENERAL : Core::ERROR_NONE;
    }

    uint32_t Exchanger::Revoke(Core::ProxyType<IExchange::ICallback> onResponse)
    {
        // TODO: take this shit out real quick
        LicenseRequestData request = { Core::ProxyType<Web::Request>::Create(), onResponse, 0 };
        _queue.Remove(request);
    }

    Exchanger::Challenger::Challenger(Exchanger& parent, Core::Event& resReceived)
        : Exchanger::Challenger::WebLinkClass(2, parent, false, Core::NodeId(), Core::NodeId(), 2048, 2048)
        , _resReceived(resReceived)
    {
    }

    Core::ProxyType<Web::Response> Exchanger::Challenger::Response()
    {
        return _response;
    }

    void Exchanger::Challenger::LinkBody(Core::ProxyType<Web::Response>& element)
    {
        element->Body<Web::TextBody>(_responseBody);
    }

    void Exchanger::Challenger::Received(Core::ProxyType<Web::Response>& res)
    {
        _response = res;
        _resReceived.SetEvent();
    }

    void Exchanger::Challenger::Send(const Core::ProxyType<Web::Request>& req)
    {
        Submit(req);
    }

    void Exchanger::Challenger::StateChange()
    {
        TRACE_L1("CENCDecryptor::Exchanger::StateChange() not implemented");
    }
}
}
