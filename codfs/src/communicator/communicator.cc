/**
 * communicator.cc
 */

#include <iostream>
#include <mutex>
#include <thread>
#include <sys/types.h>		// required by select()
#ifndef _WIN32
#include <unistd.h>		// required by select()
#include <sys/select.h>	// required by select()
#include <sys/ioctl.h>
#include <arpa/inet.h>
#else
#include <WinSock2.h>
#endif
#include <boost/thread/thread.hpp>
#include "connection.hh"
#include "communicator.hh"
#include "component.hh"
#include "socketexception.hh"
#include "../config/config.hh"
#include "../common/garbagecollector.hh"
#include "../common/enums.hh"
#include "../common/enumtostring.hh"
#include "../common/debug.hh"
#include "../common/define.hh"
#include "../common/memorypool.hh"
#include "../common/convertor.hh"
#include "../common/segmentdata.hh"
#include "../protocol/message.pb.h"
#include "../protocol/messagefactory.hh"
#include "../protocol/handshake/handshakerequest.hh"
#include "../protocol/handshake/handshakereply.hh"
#include "../protocol/transfer/putsegmentinitrequest.hh"
#include "../protocol/transfer/segmenttransferendrequest.hh"
#include "../protocol/transfer/segmentdatamsg.hh"
#include "../protocol/transfer/putsmallsegmentrequest.hh"
#include "../common/netfunc.hh"

#ifdef COMPILE_FOR_MONITOR
#include "../monitor/monitor.hh"
extern Monitor* monitor;
#endif

#ifdef COMPILE_FOR_OSD
#include "../osd/osd.hh"
extern Osd* osd;
#endif

#ifdef COMPILE_FOR_CLIENT
#include "../client/client.hh"
extern Client* client;
#endif

using namespace std;

#include <boost/bind.hpp>
#include "../../lib/threadpool/threadpool.hpp"
using namespace boost::threadpool;

pool _parsingtp;
pool threadPools[MSGTYPE_END];

// global variable defined in each component
extern ConfigLayer* configLayer;

// mutex
boost::shared_mutex connectionMapMutex;
boost::shared_mutex threadPoolMapMutex;

const uint32_t MSG_HEADER_SIZE = sizeof(struct MsgHeader);

Communicator::Communicator() {

    // verify protobuf version
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    // initialize variables
    _requestId = 0;
    _updateId = 0;
    _maxFd = 0;
//    _connectionMap = {};

//    _sockfdBufMap = {};

    // select timeout
    _timeoutSec = configLayer->getConfigInt("Communication>SelectTimeout>sec");
    _timeoutUsec = configLayer->getConfigInt(
            "Communication>SelectTimeout>usec");

    // chunk size
    _chunkSize = stringToByte(
            configLayer->getConfigString("Communication>ChunkSize"));

    // default: use random port
    _serverPort = 0;

    _pollingInterval = configLayer->getConfigInt(
            "Communication>SendPollingInterval");

	int forwardMode = configLayer->getConfigInt("Communication>ForwardMode");
	if (forwardMode == 1) {
		_forwardMode = true;
		_forwardIp = configLayer->getConfigString("Communication>ForwardServer");
	} else {
		_forwardMode = false;
		_forwardIp = "";
	}

    debug("%s\n", "Communicator constructed");

}

Communicator::~Communicator() {
    debug("%s\n", "Communicator destructed");
}

void Communicator::createServerSocket() {

    // create a socket for accepting new peers
    if (!_serverSocket.create()) {
        throw SocketException("Could not create server socket.");
    }

    if (!_serverSocket.bind(_serverPort)) {
        throw SocketException("Could not bind to port.");
    }

    if (!_serverSocket.listen()) {
        throw SocketException("Could not listen to socket.");
    }

    _serverPort = _serverSocket.getPort();

    debug("Server Port = %" PRIu16 " sockfd = %" PRIu32 "\n", _serverPort,
            _serverSocket.getSockfd());
}

/*
 * Runs in a while (1) loop
 * 1. Add serverSockfd to fd_set
 * 2. Add sockfd for all connections to fd_set
 * 3. Use select to monitor all fds
 * 4. If select returns:
 * 		serverSockfd is set : accept connection and save in map
 * 		other sockfd is set : receive a header
 * 		timeout: check if all connections are still alive
 */

void Communicator::waitForMessage() {

    map<uint32_t, Connection*>::iterator p; // connectionMap iterator

    int result; // return value for select
    fd_set sockfdSet; // fd_set for select
    struct timeval tv; // timeout for select

    const uint32_t serverSockfd = _serverSocket.getSockfd();

    // adjust _maxFd
    if (serverSockfd > _maxFd) {
        _maxFd = serverSockfd;
    }

    // each MsgType has its own threadpool
    // number of threads in each pool is defined in _threadPoolSize in the message
    // pool threadPools[MSGTYPE_END]; MOVE TO GLOBAL
    for (int i = 1; i < MSGTYPE_END; i++) { // i = 1 skip DEFAULT
        Message* tempMessage = MessageFactory::createMessage(this, (MsgType) i);
        uint32_t threadPoolSize = tempMessage->getThreadPoolSize();
        threadPools[i].size_controller().resize(threadPoolSize);
        delete tempMessage;
    }

    while (1) {

        // reset timeout
        tv.tv_sec = _timeoutSec;
        tv.tv_usec = _timeoutUsec;

        FD_ZERO(&sockfdSet);

        // add listen socket
        FD_SET(serverSockfd, &sockfdSet);

        // add all socket descriptors into sockfdSet
        {
            boost::shared_lock<boost::shared_mutex> lock(connectionMapMutex);
            for (p = _connectionMap.begin(); p != _connectionMap.end(); p++) {
                if (p->second->getIsDisconnected() == false) {
                    FD_SET(p->second->getSockfd(), &sockfdSet);
                }
            }
        }

        // invoke select
        result = select(_maxFd + 1, &sockfdSet, NULL, NULL, &tv);

        if (result < 0) {
            cerr << "select error" << endl;
            return;
        } else if (result == 0) {
            // select timeout
        } else {
            // select returns normally
        }

        // if there is a new connection
        if (FD_ISSET(_serverSocket.getSockfd(), &sockfdSet)) {

            // accept connection
            Connection* conn = new Connection();
            _serverSocket.accept(conn->getSocket());

            // add connection to _connectionMap
            {
                boost::unique_lock<boost::shared_mutex> lock(
                        connectionMapMutex);
                _connectionMap[conn->getSockfd()] = conn;
                //thread tempSendThread(&Communicator::sendMessage,this,conn->getSockfd());
                _outMessageQueue[conn->getSockfd()] = new struct LowLockQueue<
                        Message *>();
                _outDataQueue[conn->getSockfd()] = new struct LowLockQueue<
                        Message *>();
                _outBlockQueue[conn->getSockfd()] = new struct LowLockQueue<
                        Message *>();
                _dataMutex[conn->getSockfd()] = new mutex();
                _sendThread[conn->getSockfd()] = thread(
                        &Communicator::sendMessage, this, conn->getSockfd());
            }

            // Receive Optimization
            // add new socket to mutexMap and bufMap
            _sockfdBufMap[conn->getSockfd()] = new RecvBuffer();
            debug_cyan("Add socket to mutex and buf map %" PRIu32 "\n",
                    conn->getSockfd());

            debug("New connection sockfd = %" PRIu32 "\n", conn->getSockfd());

            // adjust _maxFd
            if (conn->getSockfd() > _maxFd) {
                _maxFd = conn->getSockfd();
            }
        }

        // if there is data in existing connections
        { // start critical session
            boost::upgrade_lock<boost::shared_mutex> lock(connectionMapMutex);
            p = _connectionMap.begin();
            while (p != _connectionMap.end()) {

                uint32_t sockfd = p->second->getSockfd();

                // if socket has data available
                if (FD_ISSET(sockfd, &sockfdSet)) {

                    //debug("FD_ISSET FD = %" PRIu32 "\n", sockfd);

                    // check if connection is lost
                    int nbytes = 0;
#ifndef _WIN32
					ioctl(p->second->getSockfd(), FIONREAD, &nbytes);
#else
					ioctlsocket(p->second->getSockfd(), FIONREAD, (u_long*)&nbytes);
#endif
                    if (nbytes == 0) {

                        /*
                             // upgrade shared lock to exclusive lock
                             boost::upgrade_to_unique_lock<boost::shared_mutex> uniqueLock(
                             lock);
                         */

                        // disconnect and remove from _connectionMap
                        debug("SOCKFD = %" PRIu32 " connection lost\n",
                                p->first);

                        // Receive Optimization
                        _sockfdBufMap.erase(p->first);
                        debug("SOCKET %" PRIu32 " deleted from Map\n",
                                p->first);
                        debug(
                                "SOCKFD = %" PRIu32 " delete from mutex map\n",
                                p->first);

#ifdef COMPILE_FOR_MONITOR
                        monitor->getStatModule()->removeStatBySockfd(
                                sockfd);
#endif
                        // hack: post-increment adjusts iterator even erase is called
                        //							_connectionMap.erase(p++);
                        p->second->setIsDisconnected(true);
                        p++;

                        continue;
                    } else {

                        struct RecvBuffer* rb = _sockfdBufMap[sockfd];

                        int32_t byteRead =
                                p->second->getSocket()->aggressiveRecv(
                                        rb->buf + rb->len,
                                        RECV_BUF_PER_SOCKET - rb->len);
                        rb->len += byteRead;
                        if (byteRead != 0) {
                            parsing(sockfd);
                        }
                    }
                }

                p++;
            }
        } // end critical section

    } // end while (1)

}

void Communicator::parsing(uint32_t sockfd) {
    struct RecvBuffer* recvBuffer = _sockfdBufMap[sockfd];
    debug("PARSING START FOR SOCKFD %" PRIu32 " BUF LEN = %" PRIu32 "\n",
            sockfd, recvBuffer->len);
    uint32_t idx = 0;
    struct MsgHeader *msgHeader;
    MsgType msgType;
    while (idx + MSG_HEADER_SIZE <= recvBuffer->len) {
        //memcpy((char*) &msgHeader, recvBuffer->buf + idx, MSG_HEADER_SIZE);
        msgHeader = (struct MsgHeader*) (recvBuffer->buf + idx);
        msgType = msgHeader->protocolMsgType;
        uint32_t totalMsgSize = MSG_HEADER_SIZE + msgHeader->protocolMsgSize
                + msgHeader->payloadSize;
        debug_yellow(
                "[%s] FOR SOCKET %" PRIu32 " RECV BUF SIZE %" PRIu32 " IDX = %" PRIu32 " TOTAL MSG SIZE %" PRIu32 "\n",
                EnumToString::toString(msgType), sockfd, recvBuffer->len, idx,
                totalMsgSize);
        if (idx + totalMsgSize <= recvBuffer->len) {
            char* buffer = MemoryPool::getInstance().poolMalloc(totalMsgSize);
            memcpy(buffer, recvBuffer->buf + idx, totalMsgSize);
            // DISPATCH
            threadPools[msgType].schedule(
                    boost::bind(&Communicator::dispatch, this, buffer, sockfd,
                            0));
            debug("Add Thread Pool [%s] Active: %d/Pending: %d/Size: %d\n",
                    EnumToString::toString(msgType),
                    (int )threadPools[msgType].active(),
                    (int )threadPools[msgType].pending(),
                    (int )threadPools[msgType].size());
            idx += totalMsgSize;
        } else {
            // Not receive complete message, memmove to head
            break;
        }
    }
    if (idx > 0) {
        memmove(recvBuffer->buf, recvBuffer->buf + idx, recvBuffer->len - idx);
        recvBuffer->len = recvBuffer->len - idx;
    }

}

/**
 * 1. Set a requestId for a message if it is 0
 * 2. Push the message to _outMessageQueue
 * 3. If need to wait for reply, add the message to waitReplyMessageMap
 */

void Communicator::addMessage(Message* message, bool expectReply,
        uint32_t waitOnRequestId) {

    // if requestID == 0, generate a new one
    if (message->getMsgHeader().requestId == 0) {
        message->setRequestId(generateRequestId());
    }

    // add message to waitReplyMessageMap if needed
    if (expectReply) {
        message->setExpectReply(true);
        {
            uint32_t requestId = 0;
            if (waitOnRequestId == 0) { // if a requestId is not specified
                requestId = message->getMsgHeader().requestId;
            } else {
                requestId = waitOnRequestId;
            }

            _waitReplyMessageMap.set(requestId, message);
            debug(
                    "Message (ID: %" PRIu32 " Type = %d FD = %" PRIu32 ") added to waitReplyMessageMap\n",
                    requestId, (int ) message->getMsgHeader().protocolMsgType,
                    message->getSockfd());
        }
    }

    // add message to outMessageQueue
    switch (message->getMsgHeader().protocolMsgType) {
    case SEGMENT_DATA:
        _outDataQueue[message->getSockfd()]->push(message);
        break;
    case BLOCK_DATA:
        _outBlockQueue[message->getSockfd()]->push(message);
        break;
    default:
        _outMessageQueue[message->getSockfd()]->push(message);
    }

}

Message* Communicator::popWaitReplyMessage(uint32_t requestId) {

    // check if message is in map
    if (_waitReplyMessageMap.count(requestId)) {

        // find message (and erase from map)
        Message* message = _waitReplyMessageMap.pop(requestId);

        return message;
    }
    debug("Request ID %" PRIu32 " not found in wait queue\n", requestId);
    return NULL;
}

void Communicator::sendMessage(uint32_t fd) {

    while (1) {

        vector<Message*> messages;
        Message* message;

        // send all message in the outMessageQueue
        while ((message = popMessage(fd)) != NULL) {
            messages.push_back(message);
            if (messages.size() > 10) break;
        }
        if (messages.size() > 0) {
            message = messages[0];
            const uint32_t sockfd = message->getSockfd();

            // handle disconnected component
            if (sockfd == (uint32_t) -1) {
                debug("Message (ID: %" PRIu32 ") disconnected, ignore\n",
                        message->getMsgHeader().requestId);
                debug(
                        "Deleting Message since sockfd == -1 (Type = %d ID: %" PRIu32 ")\n",
                        (int )message->getMsgHeader().protocolMsgType,
                        message->getMsgHeader().requestId);
                for (Message* message : messages) {
                    delete message;
                }
                continue;
            }

            {
                boost::shared_lock<boost::shared_mutex> lock(
                        connectionMapMutex);
                if (!(_connectionMap.count(sockfd))) {
                    debug("Connection SOCKFD = %" PRIu32 " not found!\n",
                            sockfd);
                    debug(
                            "Deleting Message since sockfd not found (Type = %d ID: %" PRIu32 ")\n",
                            (int )message->getMsgHeader().protocolMsgType,
                            message->getMsgHeader().requestId);
                    for (Message* message : messages) {
                        delete message;
                    }
                    continue;
                }
                _connectionMap[sockfd]->sendMessages(messages);
            }
        }

        usleep(_pollingInterval); // in terms of 10^-6 seconds
    }
}

/**
 * 1. Connect to target component
 * 2. Add the connection to the corresponding map
 */

uint32_t Communicator::connectAndAdd(string ip, uint16_t port,
        ComponentType connectionType) {

    // Construct a Connection segment and connect to component
    Connection* conn = new Connection();
    const uint32_t sockfd = conn->doConnect(ip, port, connectionType);

    // Save the connection into corresponding list
    {
        boost::unique_lock<boost::shared_mutex> lock(connectionMapMutex);
        _connectionMap[sockfd] = conn;
        //	thread tempSendThread(&Communicator::sendMessage,this,conn->getSockfd());
        _outMessageQueue[conn->getSockfd()] =
                new struct LowLockQueue<Message *>();
        _outDataQueue[conn->getSockfd()] = new struct LowLockQueue<Message *>();
        _outBlockQueue[conn->getSockfd()] =
                new struct LowLockQueue<Message *>();
        _dataMutex[conn->getSockfd()] = new mutex();
        _sendThread[conn->getSockfd()] = thread(&Communicator::sendMessage,
                this, conn->getSockfd());
    }

    // adjust _maxFd
    if (sockfd > _maxFd) {
        _maxFd = sockfd;
    }

    return sockfd;
}

/**
 * 1. Disconnect the connection
 * 2. Remove the connection from map
 * 3. Run the connection destructor
 */

void Communicator::disconnectAndRemove(uint32_t sockfd) {
    boost::unique_lock<boost::shared_mutex> lock(connectionMapMutex);

    if (_connectionMap.count(sockfd)) {
        Connection* conn = _connectionMap[sockfd];
        delete conn;
        _connectionMap.erase(sockfd);
        debug("Connection erased for sockfd = %" PRIu32 "\n", sockfd);
    } else {
        cerr << "Connection not found, cannot remove connection" << endl;
        exit(-1);
    }

}

uint32_t Communicator::getMdsSockfd() {
    // TODO: assume return first MDS
    map<uint32_t, Connection*>::iterator p;

    boost::shared_lock<boost::shared_mutex> lock(connectionMapMutex);

    for (p = _connectionMap.begin(); p != _connectionMap.end(); p++) {
        if (p->second->getConnectionType() == MDS) {
            return p->second->getSockfd();
        }
    }

    return -1;
}

uint32_t Communicator::getMonitorSockfd() {
    // TODO: assume return first Monitor
    map<uint32_t, Connection*>::iterator p;

    boost::shared_lock<boost::shared_mutex> lock(connectionMapMutex);

    for (p = _connectionMap.begin(); p != _connectionMap.end(); p++) {
        if (p->second->getConnectionType() == MONITOR) {
            return p->second->getSockfd();
        }
    }

    return -1;
}

uint32_t Communicator::getOsdSockfd() {
    // TODO: assume return first Osd
    map<uint32_t, Connection*>::iterator p;

    boost::shared_lock<boost::shared_mutex> lock(connectionMapMutex);

    for (p = _connectionMap.begin(); p != _connectionMap.end(); p++) {
        if (p->second->getConnectionType() == OSD) {
            return p->second->getSockfd();
        }
    }

    return -1;
}

// static function
void Communicator::handleThread(Message* message) {
    message->handle();
}

// static function
void Communicator::sendThread(Communicator* communicator) {
}

/**
 * 1. Get the MsgHeader from the receive buffer
 * 2. Get the MsgType from the MsgHeader
 * 3. Use the MessageFactory to obtain a new Message segment
 * 4. Fill in the socket descriptor into the Message
 * 5. message->parse() and fill in payload pointer
 * 6. start new thread for message->handle()
 */

void Communicator::dispatch(char* buf, uint32_t sockfd,
        uint32_t threadPoolLevel) {

    struct MsgHeader msgHeader;
    memcpy(&msgHeader, buf, sizeof(struct MsgHeader));

    debug("Running dispatch ID = %" PRIu32 " Type = %s\n", msgHeader.requestId,
            EnumToString::toString(msgHeader.protocolMsgType));

    const MsgType msgType = msgHeader.protocolMsgType;

    // delete after message is handled
    Message* message = MessageFactory::createMessage(this, msgType);

    message->setSockfd(sockfd);
    message->setRecvBuf(buf);
    message->parse(buf);

    // set payload pointer
    message->setPayload(
            buf + sizeof(struct MsgHeader) + msgHeader.protocolMsgSize);

    // debug
    message->printHeader();
    message->printProtocol();

    message->handle();
}

Message* Communicator::popMessage(uint32_t fd) {
    Message* message = NULL;
    if (_outMessageQueue[fd]->pop(message) != false) {
        return message;
    } else if (_outDataQueue[fd]->pop(message) != false) {
        return message;
    } else if (_outBlockQueue[fd]->pop(message) != false) {
        return message;
    } else
        return NULL;
}

void Communicator::waitAndDelete(Message* message) {
    GarbageCollector::getInstance().addToDeleteList(message);
}

void Communicator::setId(uint32_t id) {
    _componentId = id;
}

void Communicator::setComponentType(ComponentType componentType) {
    _componentType = componentType;
}

string Communicator::getIpPortFromSockfd (uint32_t sockfd) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(sockfd, (struct sockaddr *) &addr, &addr_len) != 0) {
        perror ("getpeername");
        debug_error ("Cannot getpeername for socket %d\n", sockfd);
    }
    char ipstr[INET_ADDRSTRLEN];
#ifndef _WIN32
	inet_ntop(AF_INET, &addr.sin_addr, ipstr, sizeof(ipstr));
#else
	WCHAR ipstr_tmp[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr.sin_addr, ipstr_tmp, INET_ADDRSTRLEN);
	wcstombs(ipstr, ipstr_tmp, INET_ADDRSTRLEN);
#endif
	return string(ipstr) + ":" + to_string(ntohs(addr.sin_port));
}

void Communicator::requestHandshake(uint32_t sockfd, uint32_t componentId,
        ComponentType componentType) {

    HandshakeRequestMsg* requestHandshakeMsg = new HandshakeRequestMsg(this,
            sockfd, componentId, componentType);

    requestHandshakeMsg->prepareProtocolMsg();
    addMessage(requestHandshakeMsg, true);

    MessageStatus status = requestHandshakeMsg->waitForStatusChange();
    if (status == READY) {

        // retrieve replied values
        uint32_t targetComponentId =
                requestHandshakeMsg->getTargetComponentId();

        // delete message
        waitAndDelete(requestHandshakeMsg);

        // add <ID> <sockfd> mapping to map
        _componentIdMap.set(targetComponentId, sockfd);
        debug(
                "[HANDSHAKE ACK RECV] Component ID = %" PRIu32 " FD = %" PRIu32 " added to map\n",
                targetComponentId, sockfd);

    } else {
        debug_error("%s\n", "Handshake Request Failed");
        exit(-1);
    }

    string ipport = getIpPortFromSockfd(sockfd);
    debug_yellow ("Connection requested to %s\n", ipport.c_str());
}

void Communicator::handshakeRequestProcessor(uint32_t requestId,
        uint32_t sockfd, uint32_t componentId, ComponentType componentType) {

    // add ID -> sockfd mapping to map
    _componentIdMap.set(componentId, sockfd);

    debug(
            "[HANDSHAKE SYN RECV] Component ID = %" PRIu32 " FD = %" PRIu32 " added to map\n",
            componentId, sockfd);

    // save component type into connectionMap
    _connectionMap[sockfd]->setConnectionType(componentType);

    // prepare reply message
    HandshakeReplyMsg* handshakeReplyMsg = new HandshakeReplyMsg(this,
            requestId, sockfd, _componentId, _componentType);
    handshakeReplyMsg->prepareProtocolMsg();
    addMessage(handshakeReplyMsg, false);

    // print welcome message
    string ipport = getIpPortFromSockfd(sockfd);
    debug_yellow ("Connection accepted from %s\n", ipport.c_str());
}

vector<struct Component> Communicator::parseConfigFile(string componentType) {
    vector<struct Component> componentList;

    // get count
    const string componentCountQuery = "Components>" + componentType + ">count";
    const uint32_t componentCount = configLayer->getConfigInt(
            componentCountQuery.c_str());

    for (uint32_t i = 0; i < componentCount; i++) {
        const string idQuery = "Components>" + componentType + ">"
                + componentType + to_string(i) + ">id";
        const string ipQuery = "Components>" + componentType + ">"
                + componentType + to_string(i) + ">ip";
        const string portQuery = "Components>" + componentType + ">"
                + componentType + to_string(i) + ">port";

        const uint32_t id = configLayer->getConfigInt(idQuery.c_str());
        const string ip = configLayer->getConfigString(ipQuery.c_str());
        const uint32_t port = configLayer->getConfigInt(portQuery.c_str());

        struct Component component;

        if (componentType == "MDS")
            component.type = MDS;
        else if (componentType == "OSD")
            component.type = OSD;
        else if (componentType == "MONITOR")
            component.type = MONITOR;
        else if (componentType == "CLIENT")
            component.type = CLIENT;

		if (_forwardMode) {
        	component.ip = _forwardIp;
		} else 
        	component.ip = ip;

        component.id = id;
        component.port = (uint16_t) port;

        componentList.push_back(component);
    }

    return componentList;
}

void Communicator::printComponents(string componentType,
        vector<Component> componentList) {

    cout << "========== " << componentType << " LIST ==========" << endl;
    for (Component component : componentList) {
        if (_componentId == component.id) {
            cout << "(*)";
        }
        cout << "ID: " << component.id << " IP: " << component.ip << ":"
                << component.port << endl;
    }
}

void Communicator::connectToComponents(vector<Component> componentList) {

    // if I am a CLIENT, always connect
    // if I am not a CLIENT, connect if My ID > Peer ID

    for (Component component : componentList) {
        if (_componentType == CLIENT || _componentId > component.id) {
            debug("Connecting to %s:%" PRIu16 "\n", component.ip.c_str(),
                    component.port);
            uint32_t sockfd = connectAndAdd(component.ip, component.port,
                    component.type);

            // send HandshakeRequest
            requestHandshake(sockfd, _componentId, _componentType);

        } else if ((_componentType == MDS || _componentType == OSD)
                && component.type == MONITOR) {
            debug("Connecting to %s:%" PRIu16 "\n", component.ip.c_str(),
                    component.port);
            uint32_t sockfd = connectAndAdd(component.ip, component.port,
                    component.type);

            // send HandshakeRequest
            requestHandshake(sockfd, _componentId, _componentType);

        } else {
            debug("Skipping %s:%" PRIu16 "\n", component.ip.c_str(),
                    component.port);
        }
    }
}

void Communicator::connectToMyself(string ip, uint16_t port,
        ComponentType type) {
    uint32_t sockfd = connectAndAdd(ip, port, type);
    _sockfdBufMap[sockfd] = new RecvBuffer();
    debug_cyan("connectToMySelf: Add socket to mutex and buf map %" PRIu32 "\n",
            sockfd);
    requestHandshake(sockfd, _componentId, _componentType);
}

void Communicator::connectToMonitor() {
    vector<Component> monitorList = parseConfigFile("MONITOR");
    printComponents("MONITOR", monitorList);
    for (Component component : monitorList) {
        uint32_t sockfd = connectAndAdd(component.ip, component.port,
                component.type);
        _sockfdBufMap[sockfd] = new RecvBuffer();
        debug_cyan(
                "connectToMonitor: Add socket to mutex and buf map %" PRIu32 "\n",
                sockfd);
        requestHandshake(sockfd, _componentId, _componentType);
    }
}

void Communicator::connectToMds() {
    vector<Component> mdsList = parseConfigFile("MDS");
    printComponents("MDS", mdsList);
    for (Component component : mdsList) {
        uint32_t sockfd = connectAndAdd(component.ip, component.port,
                component.type);
        _sockfdBufMap[sockfd] = new RecvBuffer();
        debug_cyan(
                "connectToMds: Add socket to mutex and buf map %" PRIu32 "\n",
                sockfd);
        requestHandshake(sockfd, _componentId, _componentType);
    }
}

void Communicator::connectToOsd(uint32_t dstOsdIp, uint32_t dstOsdPort) {
    uint32_t sockfd = connectAndAdd(Ipv4Int2Str(dstOsdIp), dstOsdPort,
            _componentType);
    _sockfdBufMap[sockfd] = new RecvBuffer();
    debug_cyan("connectToOsd: Add socket to mutex and buf map %" PRIu32 "\n",
            sockfd);
    requestHandshake(sockfd, _componentId, _componentType);
}

void Communicator::connectAllComponents() {

    // parse config file
    vector<Component> mdsList = parseConfigFile("MDS");
    vector<Component> osdList = parseConfigFile("OSD");
    vector<Component> monitorList = parseConfigFile("MONITOR");

    // debug
    printComponents("MDS", mdsList);
    printComponents("OSD", osdList);
    printComponents("MONITOR", monitorList);

    // connect to components
    connectToComponents(mdsList);
    connectToComponents(osdList);
    //connectToComponents(monitorList);

}

uint32_t Communicator::getSockfdFromId(uint32_t componentId) {
    if (!_componentIdMap.count(componentId)) {
        debug_error("SOCKFD for Component ID = %" PRIu32 " not found!\n",
                componentId);
        return -1;
        //exit(-1);
    } else if (_connectionMap[_componentIdMap.get(componentId)]->getIsDisconnected()) {
        return -1;
    }
    return _componentIdMap.get(componentId);
}

uint32_t Communicator::sendSegment(uint32_t componentId, uint32_t sockfd,
        struct SegmentData segmentData, CodingScheme codingScheme,
        string codingSetting) {

    string updateKey = to_string(rand());

#ifdef COMPILE_FOR_OSD
    updateKey = to_string(osd->getOsdId()) + "." + to_string(_updateId++);
#endif

#ifdef COMPILE_FOR_CLIENT
    updateKey = to_string(client->getClientId()) + "." + to_string(_updateId++);
#endif

    // pack offsets before send
    segmentData.packBuf();
    vector<offset_length_t> offsetLength = segmentData.info.offlenVector;

    debug(
            "Send segment ID = %" PRIu64 " to sockfd = %" PRIu32 " fileType = %d\n",
            segmentData.info.segmentId, sockfd, segmentData.fileType);

    const uint32_t totalSize = segmentData.bufLength;
    const uint64_t segmentId = segmentData.info.segmentId;
    char* buf = segmentData.buf;

    const uint32_t chunkCount = ((totalSize - 1) / _chunkSize) + 1;

    /*
     if (dataMsgType == DEFAULT_DATA_MSG) {
     if (segmentData.fileType == NEWFILE || segmentData.fileType == NOTFOUND || totalSize == segmentData.info.segmentSize) {
     dataMsgType = UPLOAD;
     } else {
     dataMsgType = UPDATE;
     }
     }
     */

    debug_cyan("totalSize %" PRIu32 " segmentSize %" PRIu32 "\n", totalSize,
            segmentData.info.segLength);

    // special handle for small segment and return
    if (segmentData.bufLength <= _chunkSize) {
        return putSmallSegment(componentId, sockfd, segmentId,
                segmentData.info.segLength, totalSize, codingScheme,
                codingSetting, updateKey, buf, offsetLength);
    }

    // Step 1 : Send Init message (wait for reply)

    lockDataQueue(sockfd);

    DataMsgType dataMsgType = putSegmentInit(componentId, sockfd, segmentId,
            segmentData.info.segLength, totalSize, chunkCount, codingScheme,
            codingSetting, updateKey);
    debug("%s\n", "Put Segment Init ACK-ed");

    // Step 2 : Send data chunk by chunk

    uint64_t byteToSend = 0;
    uint64_t byteProcessed = 0;
    uint64_t byteRemaining = totalSize;

    while (byteProcessed < totalSize) {

        if (byteRemaining > _chunkSize) {
            byteToSend = _chunkSize;
        } else {
            byteToSend = byteRemaining;
        }

        putSegmentData(componentId, sockfd, segmentId, buf, byteProcessed,
                byteToSend, dataMsgType, updateKey);
        byteProcessed += byteToSend;
        byteRemaining -= byteToSend;

    }

    // Step 3: Send End message

    unlockDataQueue(sockfd);

    putSegmentEnd(componentId, sockfd, segmentId, dataMsgType, updateKey,
            offsetLength);

    cout << "Put Segment ID = " << segmentId << " Finished" << endl;

    return byteProcessed;

}

void Communicator::lockDataQueue(uint32_t sockfd) {
    _dataMutex[sockfd]->lock();
}

void Communicator::unlockDataQueue(uint32_t sockfd) {
    _dataMutex[sockfd]->unlock();
}
//
// PRIVATE FUNCTIONS
//

DataMsgType Communicator::putSegmentInit(uint32_t componentId,
        uint32_t dstOsdSockfd, uint64_t segmentId, uint32_t segLength,
        uint32_t bufLength, uint32_t chunkCount, CodingScheme codingScheme,
        string codingSetting, string updateKey) {

    // Step 1 of the upload process

    PutSegmentInitRequestMsg* putSegmentInitRequestMsg =
            new PutSegmentInitRequestMsg(this, dstOsdSockfd, segmentId,
                    segLength, bufLength, chunkCount, codingScheme,
                    codingSetting, updateKey);

    putSegmentInitRequestMsg->prepareProtocolMsg();
    addMessage(putSegmentInitRequestMsg, true);

    MessageStatus status = putSegmentInitRequestMsg->waitForStatusChange();
    if (status == READY) {
        DataMsgType dataMsgType = putSegmentInitRequestMsg->getDataMsgType();
        waitAndDelete(putSegmentInitRequestMsg);
        return dataMsgType;
    } else {
        debug_error("Put Segment Init Failed %" PRIu64 "\n", segmentId);
        exit(-1);
    }
    return DEFAULT_DATA_MSG;
}

void Communicator::putSegmentData(uint32_t componentID, uint32_t dstOsdSockfd,
        uint64_t segmentId, char* buf, uint64_t offset, uint32_t length,
        DataMsgType dataMsgType, string updateKey) {

    // Step 2 of the upload process
    SegmentDataMsg* segmentDataMsg = new SegmentDataMsg(this, dstOsdSockfd,
            segmentId, offset, length, dataMsgType, updateKey);

    segmentDataMsg->prepareProtocolMsg();
    segmentDataMsg->preparePayload(buf + offset, length);

    addMessage(segmentDataMsg, false);
}

void Communicator::putSegmentEnd(uint32_t componentId, uint32_t dstOsdSockfd,
        uint64_t segmentId, DataMsgType dataMsgType, string updateKey,
        vector<offset_length_t> offsetLength) {

    // Step 3 of the upload process

    SegmentTransferEndRequestMsg* putSegmentEndRequestMsg =
            new SegmentTransferEndRequestMsg(this, dstOsdSockfd, segmentId,
                    dataMsgType, updateKey, offsetLength);

    putSegmentEndRequestMsg->prepareProtocolMsg();
    addMessage(putSegmentEndRequestMsg, true);

    MessageStatus status = putSegmentEndRequestMsg->waitForStatusChange();
    if (status == READY) {
        waitAndDelete(putSegmentEndRequestMsg);
        return;
    } else {
        debug_error("Put Segment End Failed %" PRIu64 "\n", segmentId);
        exit(-1);
    }
}

uint32_t Communicator::putSmallSegment(uint32_t componentId,
        uint32_t dstOsdSockfd, uint64_t segmentId, uint32_t segLength,
        uint32_t bufLength, CodingScheme codingScheme, string codingSetting,
        string updateKey, char* buf, vector<offset_length_t> offsetLength) {

    PutSmallSegmentRequestMsg* putSmallSegmentRequestMsg =
            new PutSmallSegmentRequestMsg(this, dstOsdSockfd, segmentId,
                    segLength, bufLength, codingScheme, codingSetting,
                    offsetLength, updateKey);
    putSmallSegmentRequestMsg->prepareProtocolMsg();
    putSmallSegmentRequestMsg->preparePayload(buf, bufLength);
    addMessage(putSmallSegmentRequestMsg, true);

    MessageStatus status = putSmallSegmentRequestMsg->waitForStatusChange();
    if (status == READY) {
        waitAndDelete(putSmallSegmentRequestMsg);
    } else {
        debug_error("Put Segment End Failed %" PRIu64 "\n", segmentId);
        exit(-1);
    }

    return bufLength;
}

uint16_t Communicator::getServerPort() {
    return _serverPort;
}

void Communicator::setServerPort(uint16_t port) {
	_serverPort = port;
}
