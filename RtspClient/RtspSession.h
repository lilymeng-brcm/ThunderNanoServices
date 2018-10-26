#ifndef RTSPSESSION_H
#define RTSPSESSION_H

#include <plugins/Logging.h>
#include <core/Queue.h>
#include <core/Thread.h>

#include "RtspParser.h"
#include "RtspSocket.h"

class RtspParser;

namespace WPEFramework {
namespace Plugin {

#define KB(x)   (x*1000)
#define MB(x)   (x*1000)


enum MyReturnCode {
    ERR_OK,
    ERR_UNKNOWN,
    ERR_ACTIVE,
    ERR_CONNECT_FAILED,
    ERR_SESSION_FAILED,
    ERR_NO_MORE,
    ERR_TIMED_OUT,

};

class RtspMessage
{
    public:
    string message;
    bool bStreamRequest;
};

typedef Core::QueueType<RtspMessage> MessageQueue;


class RtspSession : public Core::Thread
{
    public:
        RtspSession();
        ~RtspSession();
        MyReturnCode Initialize(const string& hostname, int port);
        MyReturnCode Terminate();
        MyReturnCode open(const string assetId, int start = 0, const string &reqCpeId = "", const string &remoteIp = "");
        MyReturnCode close();
        MyReturnCode play(int offset = 0, int num = 1, int denom = 1);
        MyReturnCode getProp(const string name, string &value);

        MyReturnCode getParam(bool bSRM);
        MyReturnCode sendHeartbeat(bool bSRM);
        MyReturnCode sendHeartbeats();

        MyReturnCode check(bool bSRM, int timeout, string *pStr = NULL);
        MyReturnCode checkResponse(bool bStream);
        MyReturnCode checkAnnouncement();
        MyReturnCode processAnnouncement(const std::string &response, bool bSRM);
        MyReturnCode sendResponse(int respSeq, bool bSRM);
        MyReturnCode sendAnnouncement(int code, const string &reason);

        enum Type {
            RTSP_SETUP = 1,
            RTSP_PLAY,
            RTSP_TEARDOWN,
            RTSP_GETPARAM
        };

        enum AnnounceCode {
            PlayoutStalled              = 1103,
            PlayoutResumed              = 1104,
            NewScale                    = 1500,
            EosReached                  = 2101,
            BosReached                  = 2104,
            StreamStateChange           = 2199,
            TicketExpired               = 2401,
            SessionTornDown_heartbeat   = 2403,
            SessionTornDown             = 2406,
            DataError                   = 4400,
            SvrRsrcNotAvailable         = 5200,
            InternalServerError         = 5502,
            ServerShutdown              = 5403,
            StreamChange                = 5999
        };

    private:
        uint32_t Worker ();
        inline  RtspSocket& getSocket(bool bSRM)    {
            return (bSRM || _sessionInfo.bSrmIsRtspProxy) ? _srmSocket : _controlSocket;
        }
        inline bool IsSrmRtspProxy() {
            return _sessionInfo.bSrmIsRtspProxy;
        }

    private:
        RtspSocket _srmSocket;          // XXX: Replace RtspSocket with Core::Socket
        RtspSocket _controlSocket;
        RtspParser _parser;
        RtspSessionInfo _sessionInfo;
        MessageQueue _requestQueue;
        MessageQueue _responseQueue;
        Core::CriticalSection _adminLock;

        bool _isSessionActive;
        int _nextSRMHeartbeatMS, _nextPumpHeartbearMS;
        int _playDelay;

};

}} // WPEFramework::Plugin

#endif
