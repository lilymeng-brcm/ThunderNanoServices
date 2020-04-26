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

#include "Module.h"

#include <bitset>

#include <interfaces/IBluetooth.h>
#include <interfaces/IBluetoothAudio.h>
#include <interfaces/JBluetoothAudioSink.h>


namespace WPEFramework {

namespace Plugin {

    class BluetoothAudioSink : public PluginHost::IPlugin
                             , public PluginHost::JSONRPC
                             , public Exchange::IBluetoothAudioSink {
    private:
        class Config : public Core::JSON::Container {
        public:
            Config(const Config&) = delete;
            Config& operator=(const Config&) = delete;
            Config()
                : Core::JSON::Container()
                , Controller(_T("BluetoothControl"))
            {
                Add(_T("controller"), &Controller);
            }
            ~Config() = default;

        public:
            Core::JSON::String Controller;
        }; // class Config

        class DispatchJob {
        private:
            class Job : public Core::IDispatch {
            public:
                Job(DispatchJob& parent)
                    :_parent(parent)
                {
                }
                ~Job() = default;

            public:
                void Dispatch() override
                {
                    _parent.Trigger();
                }

            private:
                DispatchJob& _parent;
            };

        public:
            using Handler = std::function<void()>;

        public:
            DispatchJob(const DispatchJob&) = delete;
            DispatchJob& operator=(const DispatchJob&) = delete;

            DispatchJob(const Handler& handler)
                : _handler(handler)
                , _job(Core::ProxyType<Job>::Create(*this))
            {
                Core::IWorkerPool::Instance().Submit(Core::ProxyType<Core::IDispatch>(_job));
            }

        private:
           ~DispatchJob() = default;

            void Trigger()
            {
                _handler();
                delete this;
            }

        private:
            Handler _handler;
            Core::ProxyType<Job> _job;
        }; // class DispatchJob

        class A2DPSink {
        private:
            class A2DPFlow {
            public:
                ~A2DPFlow() = default;
                A2DPFlow() = delete;
                A2DPFlow(const A2DPFlow&) = delete;
                A2DPFlow& operator=(const A2DPFlow&) = delete;
                A2DPFlow(const TCHAR formatter[], ...)
                {
                    va_list ap;
                    va_start(ap, formatter);
                    Trace::Format(_text, formatter, ap);
                    va_end(ap);
                }
                explicit A2DPFlow(const string& text)
                    : _text(Core::ToString(text))
                {
                }

            public:
                const char* Data() const
                {
                    return (_text.c_str());
                }
                uint16_t Length() const
                {
                    return (static_cast<uint16_t>(_text.length()));
                }

            private:
                std::string _text;
            }; // class A2DPFlow

            class DeviceCallback : public Exchange::IBluetooth::IDevice::ICallback {
            public:
                DeviceCallback() = delete;
                DeviceCallback(const DeviceCallback&) = delete;
                DeviceCallback& operator=(const DeviceCallback&) = delete;

                DeviceCallback(A2DPSink* parent)
                    : _parent(*parent)
                {
                    ASSERT(parent != nullptr);
                }
                ~DeviceCallback() = default;

            public:
                void Updated() override
                {
                    _parent.DeviceUpdated();
                }

                BEGIN_INTERFACE_MAP(DeviceCallback)
                    INTERFACE_ENTRY(Exchange::IBluetooth::IDevice::ICallback)
                END_INTERFACE_MAP

            private:
                A2DPSink& _parent;
            }; // class DeviceCallback

            static Core::NodeId Designator(const Exchange::IBluetooth::IDevice* device, const bool local, const uint16_t psm = 0)
            {
                ASSERT(device != nullptr);
                return (Bluetooth::Address((local? device->LocalId() : device->RemoteId()).c_str()).NodeId(static_cast<Bluetooth::Address::type>(device->Type()), 0 /* must be zero */, psm));
            }

            class ServiceExplorer : public Bluetooth::SDPSocket {
            private:
                class SDPFlow {
                public:
                    ~SDPFlow() = default;
                    SDPFlow() = delete;
                    SDPFlow(const SDPFlow&) = delete;
                    SDPFlow& operator=(const SDPFlow&) = delete;
                    SDPFlow(const TCHAR formatter[], ...)
                    {
                        va_list ap;
                        va_start(ap, formatter);
                        Trace::Format(_text, formatter, ap);
                        va_end(ap);
                    }
                    explicit SDPFlow(const string& text)
                        : _text(Core::ToString(text))
                    {
                    }

                public:
                    const char* Data() const
                    {
                        return (_text.c_str());
                    }
                    uint16_t Length() const
                    {
                        return (static_cast<uint16_t>(_text.length()));
                    }

                private:
                    std::string _text;
                }; // class SDPFlow

            public:
                using ClassID = Bluetooth::SDPProfile::ClassID;

                class AudioService {
                private:
                    enum attributeid : uint16_t {
                        SupportedFeatures = 0x0311
                    };

                public:
                    enum type {
                        UNKNOWN = 0,
                        SOURCE  = 1,
                        SINK    = 2,
                        NEITHER = 3
                    };

                    enum features : uint16_t {
                        NONE        = 0,
                        HEADPHONE   = (1 << 1),
                        SPEAKER     = (1 << 2),
                        RECORDER    = (1 << 3),
                        AMPLIFIER   = (1 << 4),
                        PLAYER      = (1 << 5),
                        MICROPHONE  = (1 << 6),
                        TUNER       = (1 << 7),
                        MIXER       = (1 << 8)
                    };

                public:
                    AudioService()
                        : _l2capPsm(0)
                        , _avdtpVersion(0)
                        , _a2dpVersion(0)
                        , _features(NONE)
                        , _type(UNKNOWN)
                    {
                    }
                    AudioService(const Bluetooth::SDPProfile::Service& service)
                        : AudioService()
                    {
                        using SDPProfile = Bluetooth::SDPProfile;

                        _type = NEITHER;

                        const SDPProfile::ProfileDescriptor* a2dp = service.Profile(ClassID::AdvancedAudioDistribution);
                        ASSERT(a2dp != nullptr);
                        if (a2dp != nullptr) {
                            _a2dpVersion = a2dp->Version();
                            ASSERT(_a2dpVersion != 0);

                            const SDPProfile::ProtocolDescriptor* l2cap = service.Protocol(ClassID::L2CAP);
                            ASSERT(l2cap != nullptr);
                            if (l2cap != nullptr) {
                                SDPSocket::Record params(l2cap->Parameters());
                                params.Pop(SDPSocket::use_descriptor, _l2capPsm);
                                ASSERT(_l2capPsm != 0);

                                const SDPProfile::ProtocolDescriptor* avdtp = service.Protocol(ClassID::AVDTP);
                                ASSERT(avdtp != nullptr);
                                if (avdtp != nullptr) {
                                    SDPSocket::Record params(avdtp->Parameters());
                                    params.Pop(SDPSocket::use_descriptor, _avdtpVersion);
                                    ASSERT(_avdtpVersion != 0);

                                    // It's a A2DP service using L2CAP and AVDTP protocols; finally confirm its class ID
                                    if (service.IsClassSupported(ClassID::AudioSink)) {
                                        _type = SINK;
                                    } else if (service.IsClassSupported(ClassID::AudioSource)) {
                                        _type = SOURCE;
                                    }

                                    // This one is optional...
                                    const SDPProfile::Service::AttributeDescriptor* supportedFeatures = service.Attribute(SupportedFeatures);
                                    if (supportedFeatures != nullptr) {
                                        SDPSocket::Record value(supportedFeatures->Value());
                                        value.Pop(SDPSocket::use_descriptor, _features);
                                        if (service.IsClassSupported(ClassID::AudioSource)) {
                                            _features = static_cast<features>((static_cast<uint8_t>(_features) << 4));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ~AudioService() = default;

                public:
                    type Type() const
                    {
                        return (_type);
                    }
                    uint16_t PSM() const
                    {
                        return (_l2capPsm);
                    }
                    uint16_t TransportVersion() const
                    {
                        return (_avdtpVersion);
                    }
                    uint16_t ProfileVersion() const
                    {
                        return (_a2dpVersion);
                    }
                    features Features() const
                    {
                        return (_features);
                    }

                private:
                    Bluetooth::UUID _class;
                    uint16_t _l2capPsm;
                    uint16_t _avdtpVersion;
                    uint16_t _a2dpVersion;
                    features _features;
                    type _type;
                }; // class AudioService

            public:
                ServiceExplorer() = delete;
                ServiceExplorer(const ServiceExplorer&) = delete;
                ServiceExplorer& operator=(const ServiceExplorer&) = delete;

                ServiceExplorer(A2DPSink* parent, Exchange::IBluetooth::IDevice* device, const uint16_t psm = SDP_PSM /* a well-known PSM */)
                    : Bluetooth::SDPSocket(Designator(device, true, psm), Designator(device, false, psm), 255)
                    , _parent(*parent)
                    , _device(device)
                    , _lock()
                    , _profile(ClassID::AdvancedAudioDistribution)
                {
                    ASSERT(parent != nullptr);
                    ASSERT(device != nullptr);

                    _device->AddRef();
                }
                ~ServiceExplorer() override
                {
                    Disconnect();
                    _device->Release();
                }

            private:
                bool Initialize() override
                {
                    _audioServices.clear();
                    return (true);
                }

                void Operational() override
                {
                    TRACE(SDPFlow, (_T("Bluetooth SDP connection is operational")));
                }

            public:
                 uint32_t Connect()
                {
                    uint32_t result = Open(1000);
                    if (result != Core::ERROR_NONE) {
                        TRACE(Trace::Error, (_T("Failed to open SDP socket to %s [%d]"), _device->RemoteId().c_str(), result));
                    } else {
                        TRACE(SDPFlow, (_T("Successfully opened SDP socket to %s"), _device->RemoteId().c_str()));
                    }

                    return (result);
                }
                uint32_t Disconnect()
                {
                    uint32_t result = Core::ERROR_NONE;

                    if (IsOpen() == true) {
                        result = Close(5000);
                        if (result != Core::ERROR_NONE) {
                            TRACE(Trace::Error, (_T("Failed to close SDP socket to %s [%d]"), _device->RemoteId().c_str(), result));
                        } else {
                            TRACE(SDPFlow, (_T("Successfully closed SDP socket to %s"), _device->RemoteId().c_str()));
                        }
                    }

                    return (result);
                }
                void Discover()
                {
                    if (SDPSocket::IsOpen() == true) {
                        _profile.Discover((CommunicationTimeout * 20), *this, std::list<Bluetooth::UUID>{ ClassID::AudioSink }, [&](const uint32_t result) {
                            if (result == Core::ERROR_NONE) {
                                TRACE(SDPFlow, (_T("Service discovery complete")));

                                _lock.Lock();

                                DumpProfile();

                                if (_profile.Services().empty() == false) {
                                    for (auto const& service : _profile.Services()) {
                                        if (service.IsClassSupported(ClassID::AudioSink) == true) {
                                            _audioServices.emplace_back(service);
                                        }
                                    }

                                    new DispatchJob([this]() {
                                        _parent.AudioServices(_audioServices);
                                    });
                                } else {
                                    TRACE(Trace::Information, (_T("Not an A2DP audio sink device!")));
                                }

                                _lock.Unlock();
                            } else {
                                TRACE(Trace::Error, (_T("SDP service discovery failed [%d]"), result));
                            }
                        });
                    }
                }

            private:
                void DumpProfile() const
                {
                    TRACE(SDPFlow, (_T("Discovered %d service(s)"),
                                    _profile.Services().size(), _profile.Class().Name().c_str()));

                    uint16_t cnt = 1;
                    for (auto const& service : _profile.Services()) {
                        TRACE(SDPFlow, (_T("Service %i"), cnt));
                        TRACE(SDPFlow, (_T("  Handle: 0x%08x"), service.Handle()));

                        if (service.Classes().empty() == false) {
                            TRACE(SDPFlow, (_T("  Classes:")));
                            for (auto const& clazz : service.Classes()) {
                                TRACE(SDPFlow, (_T("    - %s '%s'"),
                                                clazz.Type().ToString().c_str(), clazz.Name().c_str()));
                            }
                        }
                        if (service.Profiles().empty() == false) {
                            TRACE(SDPFlow, (_T("  Profiles:")));
                            for (auto const& profile : service.Profiles()) {
                                TRACE(SDPFlow, (_T("    - %s '%s', version: %d.%d"),
                                                profile.Type().ToString().c_str(), profile.Name().c_str(),
                                                (profile.Version() >> 8), (profile.Version() & 0xFF)));
                            }
                        }
                        if (service.Protocols().empty() == false) {
                            TRACE(SDPFlow, (_T("  Protocols:")));
                            for (auto const& protocol : service.Protocols()) {
                                TRACE(SDPFlow, (_T("    - %s '%s', parameters: %s"),
                                                protocol.Type().ToString().c_str(), protocol.Name().c_str(),
                                                protocol.Parameters().ToString().c_str()));
                            }
                        }
                    }
                }

            private:
                A2DPSink& _parent;
                Exchange::IBluetooth::IDevice* _device;
                Core::CriticalSection _lock;
                Bluetooth::SDPProfile _profile;
                std::list<AudioService> _audioServices;
            }; // class ServiceExplorer

            class AudioReceiver : public Bluetooth::AVDTPSocket {
            private:
                class AVDTPFlow {
                public:
                    ~AVDTPFlow() = default;
                    AVDTPFlow() = delete;
                    AVDTPFlow(const AVDTPFlow&) = delete;
                    AVDTPFlow& operator=(const AVDTPFlow&) = delete;
                    AVDTPFlow(const TCHAR formatter[], ...)
                    {
                        va_list ap;
                        va_start(ap, formatter);
                        Trace::Format(_text, formatter, ap);
                        va_end(ap);
                    }
                    explicit AVDTPFlow(const string& text)
                        : _text(Core::ToString(text))
                    {
                    }

                public:
                    const char* Data() const
                    {
                        return (_text.c_str());
                    }
                    uint16_t Length() const
                    {
                        return (static_cast<uint16_t>(_text.length()));
                    }

                private:
                    std::string _text;
                }; // class AVDTPFlow

            public:
                AudioReceiver() = delete;
                AudioReceiver(const AudioReceiver&) = delete;
                AudioReceiver& operator=(const AudioReceiver&) = delete;

                AudioReceiver(A2DPSink* parent, Exchange::IBluetooth::IDevice* device)
                    : Bluetooth::AVDTPSocket(Designator(device, true), Designator(device, false), 255)
                    , _parent(*parent)
                    , _device(device)
                    , _lock()
                    , _status(Exchange::IBluetoothAudioSink::UNASSIGNED)
                {
                    ASSERT(parent != nullptr);
                    ASSERT(device != nullptr);

                    _device->AddRef();
                    Status(DISCONNECTED);
                }
                ~AudioReceiver() override
                {
                    Disconnect();
                    _device->Release();
                }

            private:
                bool Initialize() override
                {
                    return (true);
                }

                void Operational() override
                {
                    TRACE(AVDTPFlow, (_T("Bluetooth AVDTP connection is operational")));
                    Status(Exchange::IBluetoothAudioSink::IDLE);
                }

            public:
                uint32_t Connect(const uint16_t psm)
                {
                    RemoteNode(Designator(_device, false, psm));

                    uint32_t result = Open(1000);
                    if (result != Core::ERROR_NONE) {
                        TRACE(Trace::Error, (_T("Failed to open AVDTP socket to %s [%d]"), _device->RemoteId().c_str(), result));
                    } else {
                        TRACE(AVDTPFlow, (_T("Successfully opened AVDTP socket to %s"), _device->RemoteId().c_str()));
                    }

                    return (result);
                }
                uint32_t Disconnect()
                {
                    uint32_t result = Core::ERROR_NONE;

                    if (IsOpen() == true) {
                        result = Close(5000);
                        if (result != Core::ERROR_NONE) {
                            TRACE(Trace::Error, (_T("Failed to close AVDTP socket to %s [%d]"), _device->RemoteId().c_str(), result));
                        } else {
                            TRACE(AVDTPFlow, (_T("Successfully closed AVDTP socket to %s"), _device->RemoteId().c_str()));
                        }
                    }

                    Status(Exchange::IBluetoothAudioSink::DISCONNECTED);

                    return (result);
                }
                Exchange::IBluetoothAudioSink::status Status() const
                {
                    return (_status);
                }

            private:
                void Status(const Exchange::IBluetoothAudioSink::status newStatus)
                {
                    _lock.Lock();
                    if (_status != newStatus) {
                        _status = newStatus;
                        Core::EnumerateType<JsonData::BluetoothAudioSink::StatusType> value(static_cast<Exchange::IBluetoothAudioSink::status>(_status));
                        TRACE(Trace::Information, (_T("Audio sink status: %s"), (value.IsSet()? value.Data() : "(undefined)")));
                    }
                    _lock.Unlock();
                }

            private:
                A2DPSink& _parent;
                Exchange::IBluetooth::IDevice* _device;
                Core::CriticalSection _lock;
                Exchange::IBluetoothAudioSink::status _status;
            }; // class AudioReceiver

        public:
            A2DPSink(const A2DPSink&) = delete;
            A2DPSink& operator= (const A2DPSink&) = delete;
            A2DPSink(BluetoothAudioSink* parent, Exchange::IBluetooth::IDevice* device)
                : _parent(*parent)
                , _device(device)
                , _callback(this)
                , _lock()
                , _explorer(this, _device)
                , _receiver(this, _device)
            {
                ASSERT(parent != nullptr);
                ASSERT(device != nullptr);

                _device->AddRef();

                if (_device->IsConnected() == true) {
                    TRACE(Trace::Fatal, (_T("The device is already connected")));
                }

                if (_device->Callback(&_callback) != Core::ERROR_NONE) {
                    TRACE(Trace::Fatal, (_T("The device is already in use")));
                }

            }
            ~A2DPSink()
            {
                if (_device->Callback(static_cast<Exchange::IBluetooth::IDevice::ICallback*>(nullptr)) != Core::ERROR_NONE) {
                    TRACE(Trace::Fatal, (_T("Could not remove the callback from the device")));
                }

                _device->Release();
            }

        public:
            void DeviceUpdated()
            {
                if (_device->IsBonded() == true) {
                    _lock.Lock();

                    if (_device->IsConnected() == true) {
                        if (_audioService.Type() == ServiceExplorer::AudioService::UNKNOWN) {
                            TRACE(A2DPFlow, (_T("Unknown device connected, attempt audio sink discovery...")));
                            // Device features are unknown at this point, so first try service discovery
                            if (_explorer.Connect() == Core::ERROR_NONE) {
                                _explorer.Discover();
                            }
                        } else if (_audioService.Type() == ServiceExplorer::AudioService::SINK) {
                            // We already know it's an audio sink, connect to transport service right away
                            TRACE(A2DPFlow, (_T("Audio sink device connected, start audio receiver...")));
                            _receiver.Connect(_audioService.PSM());
                        } else {
                            // It's not an audio sink device, can't do anything
                            TRACE(Trace::Information, (_T("Connected device does not feature an audio sink!")));
                        }
                    } else {
                        TRACE(A2DPFlow, (_T("Device diconnected")));
                        _audioService = ServiceExplorer::AudioService();
                        _explorer.Disconnect();
                        _receiver.Disconnect();
                    }

                    _lock.Unlock();
                }
            }

        public:
            Exchange::IBluetoothAudioSink::status Status() const
            {
                return (_receiver.Status());
            }

        private:
            void AudioServices(const std::list<ServiceExplorer::AudioService>& services)
            {
                ASSERT(services.empty() == false);

                if (services.size() > 1) {
                    TRACE(Trace::Information, (_T("More than one audio sink available, using the first one!")));
                }

                _lock.Lock();

                _explorer.Disconnect(); // done with SDP

                 _audioService = services.front(); // disregard possibility of multiple sink services for now
                TRACE(Trace::Information, (_T("Audio sink service available! A2DP v%d.%d, AVDTP v%d.%d, L2CAP PSM: %i, features: 0b%s"),
                                           (_audioService.ProfileVersion() >> 8), (_audioService.ProfileVersion() & 0xFF),
                                           (_audioService.TransportVersion() >> 8), (_audioService.TransportVersion() & 0xFF),
                                           _audioService.PSM(), std::bitset<8>(_audioService.Features()).to_string().c_str()));

                TRACE(A2DPFlow, (_T("Audio sink device discovered, start audio receiver...")));
                _receiver.Connect(_audioService.PSM());

                _lock.Unlock();
            }

        private:
            BluetoothAudioSink& _parent;
            Exchange::IBluetooth::IDevice* _device;
            Core::Sink<DeviceCallback> _callback;
            Core::CriticalSection _lock;
            ServiceExplorer::AudioService _audioService;
            ServiceExplorer _explorer;
            AudioReceiver _receiver;
        }; // class A2DPSink

    public:
        BluetoothAudioSink(const BluetoothAudioSink&) = delete;
        BluetoothAudioSink& operator= (const BluetoothAudioSink&) = delete;
        BluetoothAudioSink()
            : _lock()
            , _service(nullptr)
            , _sink(nullptr)
            , _controller()

        {
        }
        ~BluetoothAudioSink() = default;

    public:
        // IPlugin overrides
        const string Initialize(PluginHost::IShell* service) override;
        void Deinitialize(PluginHost::IShell* service) override;
        string Information() const override { return {}; }

    public:
        // IBluetoothAudioSink overrides
        uint32_t Assign(const string& device) override;
        uint32_t Revoke(const string& device) override;
        uint32_t Status(Exchange::IBluetoothAudioSink::status& sinkStatus) const
        {
            if (_sink) {
                sinkStatus =_sink->Status();
            } else {
                sinkStatus = Exchange::IBluetoothAudioSink::UNASSIGNED;
            }
            return (Core::ERROR_NONE);
        }

    public:
        Exchange::IBluetooth* Controller() const
        {
            return (_service->QueryInterfaceByCallsign<Exchange::IBluetooth>(_controller));
        }

    public:
        BEGIN_INTERFACE_MAP(BluetoothAudioSink)
            INTERFACE_ENTRY(PluginHost::IPlugin)
            INTERFACE_ENTRY(PluginHost::IDispatcher)
            INTERFACE_ENTRY(Exchange::IBluetoothAudioSink)
        END_INTERFACE_MAP

    private:
        mutable Core::CriticalSection _lock;
        PluginHost::IShell* _service;
        A2DPSink* _sink;
        string _controller;
    }; // class BluetoothAudioSink

} // namespace Plugin

}
