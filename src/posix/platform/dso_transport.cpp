#include "openthread/platform/dso_transport.h"
#include "system.hpp"
#include <list>
#include <memory>
#include "common/string.hpp"
#include "mbedtls/net_sockets.h"
#include "net/dns_dso.hpp"
#include "openthread/platform/srp_replication.h"
#include "posix/platform/dso_transport.hpp"
#include "posix/platform/platform-posix.h"

std::map<otPlatDsoConnection *, ot::Posix::DsoConnection *> ot::Posix::DsoConnection::sMap;

std::list<std::unique_ptr<ot::Posix::DsoConnection>> sConnections;
static bool                                          sEnabled          = true;
static bool                                          sListeningEnabled = false;
static mbedtls_net_context                           sListeningCtx;
static const uint16_t                                kListeningPort = otPlatSrplPort();

void otPlatDsoEnableListening(otInstance *aInstance, bool aEnabled)
{
    OT_UNUSED_VARIABLE(aInstance);
    OT_UNUSED_VARIABLE(aEnabled);
    VerifyOrExit(aEnabled != sListeningEnabled);

    sListeningEnabled = aEnabled;
    otLogInfoPlat("DSO listening enabled: %s", ot::ToYesNo(sListeningEnabled));
    if (sListeningEnabled)
    {
        sListeningCtx.fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        otLogInfoPlat("!!!!!!!! ifrname %s", otSysGetInfraNetifName());
        int ret;
        if ((ret = setsockopt(sListeningCtx.fd, SOL_SOCKET, SO_BINDTODEVICE, otSysGetInfraNetifName(),
                              strlen(otSysGetInfraNetifName()))) < 0)
        {
            perror("Server-setsockopt() error for SO_BINDTODEVICE");
            printf("Server-setsockopt() error for SO_BINDTODEVICE %s\n", strerror(errno));
            DieNow(1);
        }
        int n;
        if (setsockopt(sListeningCtx.fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&n, sizeof(n)) != 0)
        {
            otLogCritPlat("[trel] Failed to bind socket");
            DieNow(1);
        }
        sockaddr_in6 sockAddr;
        sockAddr.sin6_family = AF_INET6;
        sockAddr.sin6_addr   = in6addr_any;
        sockAddr.sin6_port   = ot::Encoding::BigEndian::HostSwap16(kListeningPort);
        otLogInfoPlat("INFRA INTERFACE: %s port = %d", otSysGetInfraNetifName(), sockAddr.sin6_port);

        if (bind(sListeningCtx.fd, (struct sockaddr *)&sockAddr, sizeof(sockAddr)) != 0)
        {
            otLogCritPlat("[trel] Failed to bind socket");
            DieNow(OT_EXIT_ERROR_ERRNO);
        }
        mbedtls_net_set_nonblock(&sListeningCtx);

        if (listen(sListeningCtx.fd, 10) != 0)
        {
            otLogCritPlat("[trel] Failed to listen on socket");
            DieNow(OT_EXIT_ERROR_ERRNO);
        }
        otLogCritPlat("Listening socket created!!!");

        //        int ret =
        //            mbedtls_net_bind(&sListeningCtx, nullptr, std::to_string(kListeningPort).c_str(),
        //            MBEDTLS_NET_PROTO_TCP);
        //        if (ret != 0)
        //        {
        //            otLogCritPlat("failed to listen: %s", ot::Posix::MbedErrorToString(ret));
        //        }
        //        ret = mbedtls_net_set_nonblock(&sListeningCtx);
        //        if (ret != 0)
        //        {
        //            otLogCritPlat("failed to set nonblock: %s", ot::Posix::MbedErrorToString(ret));
        //        }
        //        if (ret == 0)
        //        {
        //            otLogInfoPlat("[SUCCESS] DSO listening enabled: %s", ot::ToYesNo(sListeningEnabled));
        //        }
    }
    else
    {
        mbedtls_net_close(&sListeningCtx);
        sConnections.clear();
    }

exit:
    return;
}

void otPlatDsoConnect(otPlatDsoConnection *aConnection, const otSockAddr *aPeerSockAddr)
{
    auto conn = ot::Posix::DsoConnection::FindOrCreate(aConnection);
    IgnoreError(conn->Connect(aPeerSockAddr));
}

void otPlatDsoSend(otPlatDsoConnection *aConnection, otMessage *aMessage)
{
    OT_UNUSED_VARIABLE(aConnection);
    OT_UNUSED_VARIABLE(aMessage);

    auto conn = ot::Posix::DsoConnection::Find(aConnection);
    VerifyOrExit(conn != nullptr);
    conn->Send(aMessage);

exit:
    otMessageFree(aMessage);
}

void otPlatDsoDisconnect(otPlatDsoConnection *aConnection, otPlatDsoDisconnectMode aMode)
{
    OT_UNUSED_VARIABLE(aConnection);
    OT_UNUSED_VARIABLE(aMode);
    auto conn = ot::Posix::DsoConnection::Find(aConnection);
    VerifyOrExit(conn != nullptr);
    conn->Disconnect(aMode);

    ot::Posix::DsoConnection::sMap.erase(aConnection);

    for (auto it = sConnections.begin(); it != sConnections.end(); ++it)
    {
        if (conn == it->get())
        {
            otLogInfoPlat("!!!!! erased: %p", it->get());
            sConnections.erase(it);
            break;
        }
    }

exit:
    return;
}

void AcceptIncomingConnections(otInstance *aInstance)
{
    //    auto _ = CDLogger("Accept incoming connections");
    VerifyOrExit(sListeningEnabled);

    while (true)
    {
        //        otLogInfoPlat("$$$$$$$$$$$$$$$$$$$ waiting for incoming connections ");
        mbedtls_net_context  incomingCtx;
        uint8_t              incomingAddrBuf[sizeof(sockaddr_in6)];
        size_t               len = 0;
        otSockAddr           addr;
        in6_addr *       addrIn6;
        in_addr *       addrIn;
        otPlatDsoConnection *conn;

        int ret = mbedtls_net_accept(&sListeningCtx, &incomingCtx, &incomingAddrBuf, sizeof(incomingAddrBuf), &len);
        if (ret < 0)
        {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ)
            {
                ExitNow();
            }
            else
            {
                otLogCritPlat("!!!!! error accepting connection: %s", ot::Posix::MbedErrorToString(ret));
            }
        }
        otLogWarnPlat("!!!!! address size===== %d", len);
        if (len != OT_IP6_ADDRESS_SIZE && len != 4)
        {
            otLogWarnPlat("!!!!! unexpected address size: %d", len);
            ExitNow();
        }

        SuccessOrDie(mbedtls_net_set_nonblock(&incomingCtx));

        if (len == OT_IP6_ADDRESS_SIZE) {  // TODO: the way of handling addr may be wrong
            addrIn6 = reinterpret_cast<in6_addr *>(incomingAddrBuf);
            memcpy(&addr.mAddress.mFields.m8, &addrIn6, len);
            addr.mPort = 0;  // TODO
        } else if (len == 4) {
            addrIn = reinterpret_cast<in_addr *>(incomingAddrBuf);
            memset(&addr.mAddress, 0, sizeof(addr.mAddress));
            memcpy(addr.mAddress.mFields.m32 + 3, &addrIn, len);
            addr.mAddress.mFields.m16[5] = 0xff;
            addr.mAddress.mFields.m16[6] = 0xff;
            addr.mPort = 0;  // TODO
            otLogWarnPlat("!!!!! IPV4 incoming connection: %u", addrIn);
        } else {
            otLogWarnPlat("!!!!! unknown address type !!!! ");
            ExitNow();
        }
        conn       = otPlatDsoAccept(aInstance, &addr);

        otLogWarnPlat("!!!!! accepting connection: %16x", incomingAddrBuf);

        if (conn != nullptr)
        {
            otPlatDsoHandleConnected(conn);
            ot::Posix::DsoConnection::Create(conn, incomingCtx)->mConnected = true;
            otLogWarnPlat("handle connected !!!!");
        }
        else
        {
            char buf[50];
            otIp6AddressToString(reinterpret_cast<otIp6Address *>(&addr.mAddress), buf, sizeof(buf));
            otLogWarnPlat("!!!! failed to accept connection: %s %d", buf, addr.mPort);
        }
    }
exit:
    return;
}

void platformDsoProcess(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);

    auto _ = CDLogger("platform Dso Process");

    VerifyOrExit(sEnabled);

    ot::Posix::DsoConnection::ProcessAll();
    AcceptIncomingConnections(aInstance);

exit:
    return;
}