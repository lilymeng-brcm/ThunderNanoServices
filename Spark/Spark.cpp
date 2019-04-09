#include "Spark.h"

namespace WPEFramework {

namespace Spark {

    extern Exchange::IMemory* MemoryObserver(const uint32_t pid);
}

namespace Plugin {

    SERVICE_REGISTRATION(Spark, 1, 0);

    static Core::ProxyPoolType<Web::TextBody> _textBodies(2);
    static Core::ProxyPoolType<Web::JSONBodyType<Spark::Data>> jsonBodyDataFactory(2);

    /* encapsulated class Thread  */
    /* virtual */ const string Spark::Initialize(PluginHost::IShell* service)
    {
        Config config;
        string message;

        ASSERT(_service == nullptr);
        ASSERT(_spark == nullptr);
        ASSERT(_memory == nullptr);

        config.FromString(service->ConfigLine());

        _pid = 0;
        _service = service;
        _skipURL = _service->WebPrefix().length();

        // Register the Process::Notification stuff. The Remote process might die
        // before we get a
        // change to "register" the sink for these events !!! So do it ahead of
        // instantiation.
        _service->Register(&_notification);

        _spark = _service->Root<Exchange::IBrowser>(_pid, 2000, _T("SparkImplementation"));

        if (_spark != nullptr) {

            PluginHost::IStateControl* stateControl(_spark->QueryInterface<PluginHost::IStateControl>());

            if (stateControl == nullptr) {
                _spark->Release();
                _spark = nullptr;
            } else {

                _memory = WPEFramework::Spark::MemoryObserver(_pid);

                ASSERT(_memory != nullptr);

                _spark->Register(&_notification);
                stateControl->Register(&_notification);
                stateControl->Configure(_service);

                stateControl->Release();
            }
        }

        if (_spark == nullptr) {
            message = _T("Spark could not be instantiated.");
            _service->Unregister(&_notification);
            _service = nullptr;
        }

        return message;
    }

    /* virtual */ void Spark::Deinitialize(PluginHost::IShell* service)
    {
        ASSERT(_service == service);
        ASSERT(_spark != nullptr);
        ASSERT(_memory != nullptr);

        PluginHost::IStateControl* stateControl(
            _spark->QueryInterface<PluginHost::IStateControl>());

        // Make sure the Activated and Deactivated are no longer called before we
        // start cleaning up..
        _service->Unregister(&_notification);
        _spark->Unregister(&_notification);
        _memory->Release();

        // In case Spark crashed, there is no access to the statecontrol interface,
        // check it !!
        if (stateControl != nullptr) {
            stateControl->Unregister(&_notification);
            stateControl->Release();
        } else {
            // On behalf of the crashed process, we will release the notification sink.
            _notification.Release();
        }

        if (_spark->Release() != Core::ERROR_DESTRUCTION_SUCCEEDED) {

            ASSERT(_pid != 0);

            TRACE_L1("Spark Plugin is not properly destructed. %d", _pid);

            RPC::IRemoteProcess* process(_service->RemoteProcess(_pid));

            // The process can disappear in the meantime...
            if (process != nullptr) {
                process->Terminate();
                process->Release();
            }
        }

        // Deinitialize what we initialized..
        _memory = nullptr;
        _spark = nullptr;
        _service = nullptr;
    }

    /* virtual */ string Spark::Information() const
    {
        // No additional info to report.
        return (string());
    }

    /* virtual */ void Spark::Inbound(Web::Request& request)
    {
        if (request.Verb == Web::Request::HTTP_POST) {
            // This might be a "launch" application thingy, make sure we receive the
            // proper info.
            request.Body(jsonBodyDataFactory.Element());
            //request.Body(_textBodies.Element());
        }
    }

    /* virtual */ Core::ProxyType<Web::Response>
    Spark::Process(const Web::Request& request)
    {
        ASSERT(_skipURL <= request.Path.length());

        TRACE(Trace::Information, (string(_T("Received spark request"))));

        Core::ProxyType<Web::Response> result(
            PluginHost::Factories::Instance().Response());

        Core::TextSegmentIterator index(
            Core::TextFragment(request.Path, _skipURL,
                request.Path.length() - _skipURL),
            false, '/');

        result->ErrorCode = Web::STATUS_BAD_REQUEST;
        result->Message = "Unknown error";


        if (request.Verb == Web::Request::HTTP_POST) {
            // We might be receiving a plugin download request.
            if ((index.Next() == true) && (index.Next() == true) && (_spark != nullptr)) {
                PluginHost::IStateControl* stateControl(_spark->QueryInterface<PluginHost::IStateControl>());
                if (stateControl != nullptr) {
                    if (index.Remainder() == _T("Suspend")) {
                        stateControl->Request(PluginHost::IStateControl::SUSPEND);
                    }
                    else if (index.Remainder() == _T("Resume")) {
                        stateControl->Request(PluginHost::IStateControl::RESUME);
                    }
                    else if ((index.Remainder() == _T("URL")) && (request.HasBody() == true) && (request.Body<const Data>()->URL.Value().empty() == false)) {
                        _spark->SetURL(request.Body<const Data>()->URL.Value());
                    }
                    stateControl->Release();
                }
            }
        } else if (request.Verb == Web::Request::HTTP_GET) {
        }

        return result;
    }

    /* ---------------------------------------------------------
    void Spark::StateChange(const Exchange::ISpark::state state)
    {
        switch (state) {
        case Exchange::ISpark::STOPPED:
            TRACE(Trace::Information,
                (string(_T("StateChange: { \"playing\":false }"))));
            _service->Notify("{ \"playing\":false }");
            break;
        case Exchange::ISpark::PLAYING:
            TRACE(Trace::Information,
                (string(_T("StateChange: { \"playing\":true }"))));
            _service->Notify("{ \"playing\":true }");
            break;
        case Exchange::ISpark::SUSPENDING:
            break;
        default:
            ASSERT(false);
            break;
        }
    }
    ------------------------------------------------------------- */

    void Spark::StateChange(const PluginHost::IStateControl::state state)
    {
        switch (state) {
        case PluginHost::IStateControl::RESUMED:
            TRACE(Trace::Information,
                (string(_T("StateChange: { \"suspend\":false }"))));
            _service->Notify("{ \"suspended\":false }");
            break;
        case PluginHost::IStateControl::SUSPENDED:
            TRACE(Trace::Information,
                (string(_T("StateChange: { \"suspend\":true }"))));
            _service->Notify("{ \"suspended\":true }");
            break;
        case PluginHost::IStateControl::EXITED:
            // Exited by Spark app
            PluginHost::WorkerPool::Instance().Submit(PluginHost::IShell::Job::Create(
                _service, PluginHost::IShell::DEACTIVATED,
                PluginHost::IShell::REQUESTED));
            break;
        case PluginHost::IStateControl::UNINITIALIZED:
            break;
        default:
            ASSERT(false);
            break;
        }
    }

    void Spark::Deactivated(RPC::IRemoteProcess* process)
    {
        if (process->Id() == _pid) {

            ASSERT(_service != nullptr);

            PluginHost::WorkerPool::Instance().Submit(PluginHost::IShell::Job::Create(
                _service, PluginHost::IShell::DEACTIVATED,
                PluginHost::IShell::FAILURE));
        }
    }
}
} // namespace