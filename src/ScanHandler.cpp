//
// NetMap - C++ Network Scanner
// ---------------------------
// ScanHandler:
// Deals with all major networking processes related to scanning.
// ---------------------------
//
//GPLV2.0 License
//
//Copyright(c)[2024][Joseph  Frary]
//
//This program is free software; you can redistribute it and /or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; either version 2 of the License, or
//(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, see < https://www.gnu.org/licenses/>.

#include "ScanHandler.h"
#include "ResourceHandler.h"
#include "resource.h"
#include "utils.h"
#include <stdexcept>
#include <format>
#include <atomic>
#include <conio.h>
#include <stdio.h>
#pragma comment (lib, "Mswsock.lib")
#include <WinSock2.h>
#pragma comment(lib, "ws2_32")
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include<IcmpAPI.h>
#include <iostream>
#include <thread>
#include <future>
#pragma comment(lib, "iphlpapi.lib")
#include <algorithm>
#include <random>
#include <iterator>
#include <vector>
#include <limits.h>
#include <sstream>
#include <string>
#include <map>

constexpr int ICMP_MAX_TRIES = 3;
constexpr int ICMP_DATA_SIZE = 64;
constexpr int ICMP_REPLY_TIMEOUT = 256;
char const constexpr* const SERVICE_FILE_PATH = "known-services";
char const constexpr* const SERVICE_RESOURCE_PATH = "SERVICE_LIST";
constexpr int SERVICE_RESOURCE_ID = 255;

class NetException : public std::runtime_error {
public:
    NetException(const std::string& message)
        : std::runtime_error(message) {}
};

/// <summary>
/// run wsastartup and return hints struct for later use.
/// only call once, if windows clean up has not been called since.
/// </summary>
/// <returns>addrinfo hints</returns>
static struct addrinfo getWSA()
{
    WSADATA wsaData;
    struct addrinfo hints;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        WSACleanup();
        throw NetException(
            "WSAStartup failed\n"
        );
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    return hints;
}
// Port with only a number given
NetworkPort::NetworkPort(int portNumber)
{
    this->portNumber = portNumber;
    this->portReason = 0;
    this->portStatus = false;
}
// Port with a open/close state and a error code
NetworkPort::NetworkPort(int portNumber, bool portStatus, int portReason)
{
    this->portNumber = portNumber;
    this->portStatus = portStatus;
    this->portReason = portReason;
}

bool NetworkPort::getStatus()
{
    return this->portStatus;
}

int NetworkPort::getNumber()
{
    return this->portNumber;
}

/*
Use this nifty functions to sort ports more easily.
*/
bool NetworkPort::operator<(const NetworkPort& netPort)
{
    return this->portNumber < netPort.portNumber;
}

bool NetworkPort::operator<=(const NetworkPort& netPort)
{
    return this->portNumber <= netPort.portNumber;
}
bool NetworkPort::operator>(const NetworkPort& netPort)
{
    return this->portNumber > netPort.portNumber;
}
bool NetworkPort::operator>=(const NetworkPort& netPort)
{
    return this->portNumber >= netPort.portNumber;
}

// Given the full map of services get the service that should be present for a given port.
std::string NetworkPort::getExpectedService(std::map<int,std::string> serviceMap)
{
    try
    {
        std::string serviceName = serviceMap.at(this->getNumber());
        if (serviceName.size() == 0)
        {
            return std::string("unkown");
        }
        return serviceName;
    }
    catch (const std::exception&)
    {
        return std::string("unknown");
    }

}

/// build the map of known services from the resource file 
std::map<int,std::string> loadKnownServices()
{
    Resource ServiceResource(SERVICE_LIST,"TEXT");
    auto resourceContents = ServiceResource.GetResourceString();

    if (resourceContents.size() == 0)
    {
        throw NetException("Failed to load resources file\n"); 
    }

    std::istringstream serviceFile(resourceContents.data());
    std::map<int, std::string> serviceMap;
    std::string fileLine{};
    
    int res;
    char serviceName[256];
    char serviceType[32];
    int portNumber;

    while (std::getline(serviceFile,fileLine))
    {
        
        if (fileLine[0] == '#')
        {
            continue;
        }
        res = sscanf_s(fileLine.c_str(), "%127s %d/%15s", serviceName, sizeof(serviceName), &portNumber, serviceType, sizeof(serviceType));
        if (res == 3)
        {
            if (strcmp(serviceName, "unknown") != 0 && strcmp(serviceType,"tcp") == 0)
            {
                serviceMap[portNumber] = serviceName;
            }
        }
    }
    return serviceMap;
}

// node with a list of ports
NetworkNode::NetworkNode(std::string hostAddress, std::vector<NetworkPort> hostPorts)
{
    this->networkAddress = hostAddress;
    this->requestedPorts = hostPorts;
}

NetworkNode::NetworkNode(std::string hostAddress, std::vector<int> targetPorts, bool pingResult)
{
    this->networkAddress = hostAddress;
    this->isActive = pingResult;
    this->requestedPorts.insert(this->requestedPorts.end(), targetPorts.begin(), targetPorts.end());
}

// node with no ports but an ICMP status
NetworkNode::NetworkNode(std::string hostAddress, bool pingResult)
{
    this->networkAddress = hostAddress;
    this->isActive = pingResult;
}

std::string NetworkNode::getName()
{
    return this->networkAddress;
}

std::vector<NetworkPort> NetworkNode::getPorts()
{
    return this->portResults;
}

void NetworkNode::appendPort(NetworkPort newPort)
{
    this->requestedPorts.push_back(newPort);
}

void NetworkNode::appendPorts(std::vector<NetworkPort> newPorts)
{
    this->portResults.insert(this->portResults.end(), newPorts.begin(), newPorts.end());
}

void NetworkNode::setPorts(std::vector<NetworkPort> newPorts)
{
    this->portResults = newPorts;
}

void NetworkNode::setActive()
{
    this->isActive = true;
}

bool NetworkNode::getActive()
{
    return this->isActive;
}

std::vector<NetworkPort> NetworkNode::getActivePorts()
{
    std::vector<NetworkPort> activePorts;
    for (NetworkPort port : this->portResults)
    {
        if (port.getStatus())
        {
            activePorts.push_back(port);
        }
    }
    return activePorts;
}

std::vector<NetworkPort> NetworkNode::getRequestedPorts()
{
    return this->requestedPorts;
}

void NetworkNode::setMac(std::string macAddr)
{
    this->macAddr = macAddr;
}

std::string NetworkNode::getMac()
{
    return this->macAddr;
}

ScanHandler::ScanHandler(std::vector<std::string> targetAddresses, std::vector<int> targetPorts, int maxThreads, int networkDelay)
{
    this->maxThreads = maxThreads;
    this->networkDelay = networkDelay;
    this->hostNames = targetAddresses;
    ScanMonitor scanValues = this->scanMonitor.load();
    scanValues.networkDelay = this->networkDelay;
    this->scanMonitor.store(scanValues);
    this->serviceMap = loadKnownServices();
    for (std::string hostAddress : targetAddresses)
    {
        this->targetHosts.push_back(
            NetworkNode(hostAddress, targetPorts, false)
        );
    }
}

bool handleConsole(std::atomic<ScanMonitor>& scanMonitor)
{
    std::cout << "Press q to exit, s for status\n";
    while (true)
    {
        ScanMonitor scanValues = scanMonitor.load();
        if (!scanValues.threadsEnabled)
        {
            return 0;
        }
        int charInput = _kbhit() ? _getch() : -1;
        if (charInput == 'q')
        {
            std::cout << "Quitting Early!\n";
            scanValues.threadsEnabled = false;
            scanMonitor.store(scanValues);
            return 0;
        }
        else if (charInput == 's')
        {
            std::cout << std::format("Completed: {} Hosts, {} Ports\n", scanValues.hostsDone, scanValues.portsDone);
        }
        else if (charInput > 0)
        {
            std::cout << "Press q to exit, s for status\n";
        }
    }
}

static std::string ARPHost(std::string targetHost)
{
    DWORD arpRetVal;
    ULONG macAddr[2];
    ULONG macAddrLen = 6;
    sockaddr_in addr = {};
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    BYTE *macFormated;

    std::ostringstream macString{};

    if (inet_pton(AF_INET, targetHost.c_str(), &addr.sin_addr) != 1)
    {
        throw NetException(std::format("Failed to convert address: {}", targetHost));
    }
    
    arpRetVal = SendARP(addr.sin_addr.s_addr, INADDR_ANY, &macAddr, &macAddrLen);
    if (arpRetVal == NO_ERROR)
    {
        if (macAddrLen == 0)
        {
            return "";
        }
        else
        {
            macFormated = (BYTE*)&macAddr;
            for (size_t i = 0; i < (int) macAddrLen; i++)
            {
                if (i == (macAddrLen - 1)) {
                    macString << std::format("{:02X}", macFormated[i]);
                }
                else
                {
                    macString << std::format("{:02X}-", macFormated[i]);
                }
            }
        }
        return macString.str();
    }
    else
    {
        switch (arpRetVal)
        {
        case ERROR_BAD_NET_NAME:
            throw NetException("ARP target could not be resolved");
        case ERROR_NOT_SUPPORTED:
            throw NetException("ARP is not supported on this device");
        default:
            return "";
        }
    }

}

/// <summary>
/// Ping a single host and return its status
/// </summary>
/// <param name="targetHost">host to ping</param>
/// <returns>true if ICMP is replied to, false if no reply is given or error occurs</returns>
static bool pingHost(std::string targetHost, std::string& macAddr)
{
    int currentAttempts = 0;
    sockaddr_in addr = {};
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    HANDLE ICMPFile;
    ICMPFile = IcmpCreateFile();

    void* replyBuffer = nullptr;
    std::string macString{};

    if (inet_pton(AF_INET, targetHost.c_str(), &addr.sin_addr) != 1)
    {
        throw NetException(std::format("Failed to convert address: {}", targetHost));
    }

    unsigned long IPAddr = addr.sin_addr.s_addr;

    if (IPAddr == INADDR_NONE)
    {
        return false;
    }

    while (currentAttempts < ICMP_MAX_TRIES)
    {
        std::string sendData = randomString(ICMP_DATA_SIZE);
        DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sendData.size();
        replyBuffer = malloc(replySize);

        if (replyBuffer == nullptr)
        {
            throw NetException("Failed to allocate memory for ping attempt\n");
        }

        DWORD replyCount = IcmpSendEcho(
            ICMPFile, IPAddr, (void*)sendData.c_str(), sendData.size(), NULL,
            replyBuffer, replySize, ICMP_REPLY_TIMEOUT
        );
        PICMP_ECHO_REPLY echoReply = (PICMP_ECHO_REPLY)replyBuffer;

        if (replyCount != 0)
        {
            if (echoReply->Status == IP_SUCCESS)
            {
                macAddr = ARPHost(targetHost.c_str());
                return true;
            }
            else if (echoReply->Status == IP_DEST_HOST_UNREACHABLE)
            {
                return false;
            }
            std::cout << std::format("Got non standard error: {} for host: {}", echoReply->Status, targetHost) << std::endl;
            return false;
        }
        int errorCode = GetLastError();
        currentAttempts++;
    }
    if (replyBuffer != nullptr)
    {
        free(replyBuffer);
    }
    return false;
}

static std::vector<tempResult> pingHosts(std::vector<std::string> targetHosts, std::atomic<ScanMonitor>& scanMonitor)
{
    std::vector<tempResult> pingResults;
    for (std::string host : targetHosts)
    {
        ScanMonitor scanValues = scanMonitor.load();
        if (scanValues.threadsEnabled == true)
        {
            std::string macAddr;
            bool pingResult = pingHost(host,macAddr);
            pingResults.push_back(
                { host,pingResult,macAddr }
            );
            std::this_thread::sleep_for(std::chrono::milliseconds(scanValues.networkDelay));
            scanValues = scanMonitor.load();
            scanValues.hostsDone += 1;
            scanMonitor.store(scanValues);
        }
        else
        {
            return pingResults;
        }
    }
    return pingResults;
}

void ScanHandler::pingSweep(bool isVerbose)
{
    int hostCount = this->hostNames.size();
    int finalThreads = this->maxThreads;
    int pingRange;

    // disable threading when number of hosts is too smal
    if (hostCount < finalThreads)
    {
        finalThreads = 1;
        pingRange = hostCount;
        if (isVerbose)
        {
            std::cout << "Too many threads for host count, disabling multithreading." << std::endl;
        }
    }
    else
    {
        pingRange = (hostCount + finalThreads - 1) / finalThreads;
    }

    std::thread consoleThread(handleConsole, std::ref(this->scanMonitor));
    std::vector<std::future<std::vector<tempResult>>> futures;
    std::vector<std::string> pingTargets = this->hostNames;

    auto rd = std::random_device();
    auto rng = std::default_random_engine{ rd() };

    for (size_t i = 0; i < finalThreads; i++)
    {
        std::vector<std::string> threadHosts;
        std::sample(
            pingTargets.begin(),
            pingTargets.end(),
            std::back_inserter(threadHosts),
            pingRange,
            std::mt19937{ std::random_device{}() }
        );

        for (std::string host : threadHosts)
        {
            pingTargets.erase(
                std::remove(pingTargets.begin(), pingTargets.end(), host), pingTargets.end()
            );
        }
        std::shuffle(threadHosts.begin(), threadHosts.end(), rng);
        futures.push_back(
            std::async(std::launch::async, pingHosts, threadHosts, std::ref(this->scanMonitor))
        );
    }
    int pingCount = 0;
    for (auto& pingFuture: futures)
    {
        std::vector<tempResult> futureResult = pingFuture.get();
        
        for (size_t i = 0; i < futureResult.size(); i++)
        {
            for (NetworkNode& testedHost : this->targetHosts)
            {
                if (testedHost.getName() == futureResult[i].hostAddress)
                {
                    testedHost.setActive();
                    testedHost.setMac(futureResult[i].macAddr);
                }
            }
            pingCount++;
        }
        if (pingCount == hostCount)
        {
            ScanMonitor scanVals = this->scanMonitor.load();
            scanVals.threadsEnabled = false;
            this->scanMonitor.store(scanVals);
            consoleThread.join();
        }
    }
    if (consoleThread.joinable())
    {
        consoleThread.join();
    }
    windowsCleanup();
}

static int scanPort(std::string targetHost, int targetPort, addrinfo scanHints)
{
    SOCKET connectionSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL;

    std::string portString = std::to_string(targetPort);
    if (getaddrinfo(targetHost.c_str(), portString.c_str(), (addrinfo*) &scanHints, &result) != 0)
    {
        freeaddrinfo(result);
        WSACleanup();
        throw NetException(std::format("Host resolution failed for host: {}\n",targetHost));
    }
    ptr = result;
    connectionSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);


    // disable lingering connection
    // not sure this has that much of an impact
    struct linger l;
    l.l_onoff = 1;
    l.l_linger = 0;

    setsockopt(connectionSocket, SOL_SOCKET, SO_LINGER, (const char*)&l, sizeof(l));

    /*
    Override the default SYN attempt count to 0.
    This is CRITICAL to performance and reduces overall network time 
    by a factor of 10. dug around nmap to find this.
    */
    TCP_INITIAL_RTO_PARAMETERS params = { 1000, /* overall round trip time*/ TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS};
    DWORD dwval = 0;
    WSAIoctl(connectionSocket, SIO_TCP_INITIAL_RTO, &params, sizeof(params), NULL, 0, &dwval, NULL, NULL);

    
    if (connectionSocket == INVALID_SOCKET)
    {
        freeaddrinfo(result);
        WSACleanup();
        throw NetException(std::format("Failed to create socket with error: {}\n",WSAGetLastError()));
    }
    int connectionResult = connect(connectionSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
    closesocket(connectionSocket);
    freeaddrinfo(result);
    return connectionResult;
}

static NetworkNode scanHost(std::string targetHost, std::vector<int> targetPorts, addrinfo hints, std::atomic<ScanMonitor>& scanMonitor)
{
    std::vector<NetworkPort> portResults{};
    for (int port : targetPorts)
    {
        if (!scanMonitor.load().threadsEnabled)
        {
            return NetworkNode(targetHost, portResults);
        }
        int portRes = scanPort(targetHost, port, hints);
        bool portOpen = false;
        if (portRes == 0)
        {
            portOpen = true;
        }
        portResults.push_back(
            NetworkPort(port, portOpen, portRes)
        );
    }
    return NetworkNode(
        targetHost, portResults
    );
}

static std::vector<NetworkNode> scanHosts(std::vector<std::string> targetHosts, std::vector<int> targetPorts, addrinfo hints,std::atomic<ScanMonitor>& scanMonitor)
{
    std::vector<NetworkNode> hostResults{};
    for(std::string host: targetHosts)
    {
        if (!scanMonitor.load().threadsEnabled)
        {
            return hostResults;
        }
        hostResults.push_back(
            scanHost(host, targetPorts, hints, std::ref(scanMonitor))
        );

        ScanMonitor scanVals = scanMonitor.load();
        if (scanVals.networkDelay > 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(scanVals.networkDelay));
        }

    }
    ScanMonitor scanVals = scanMonitor.load();
    scanVals.portsDone += targetPorts.size();
    scanMonitor.store(scanVals);
    return hostResults;
}

void ScanHandler::printResults(bool isVerbose) {
    std::cout << SPLITTER << std::endl;
    bool allClosed = true;
    for (NetworkNode &targetHost: this->targetHosts)
    {
        std::vector<NetworkPort> activePorts = targetHost.getActivePorts();
        if (!isVerbose) {

            if (activePorts.size() == 0)
            {

                continue;
            }
            allClosed = false;

            if (targetHost.getMac().size() > 0)
            {
                std::cout << std::format("Host: {} ({})", targetHost.getName(), targetHost.getMac()) << std::endl;
            }
            else
            {
                std::cout << std::format("Host: {} (MAC UNKNOWN)", targetHost.getName()) << std::endl;
            }

            std::sort(activePorts.begin(), activePorts.end());

            for (NetworkPort activePort : activePorts)
            {
                std::cout << std::format("Port {} ({}): Open", activePort.getNumber(),
                    activePort.getExpectedService(this->serviceMap)) << std::endl;

            }
        }
        else {
            std::vector<NetworkPort> netPorts = targetHost.getPorts();
            if (netPorts.size() > 0)
            {
                std::cout << std::format("Host: {}", targetHost.getName()) << std::endl;
                for (NetworkPort netPort : netPorts)
                {
                    if (netPort.getStatus()) {
                        std::cout << std::format("Port {} ({}): Open", netPort.getNumber(),
                            netPort.getExpectedService(this->serviceMap)) << std::endl;
                        allClosed = false;
                    }
                    else if (isVerbose && !netPort.getStatus())
                    {
                        std::cout << std::format("Port {} ({}): Closed",
                            netPort.getNumber(), netPort.getExpectedService(this->serviceMap)) << std::endl;
                    }
                }

            }
        }

    }
    if (allClosed && !isVerbose)
    {
        std::cout << "No open ports found" << std::endl;
    }
    std::cout << SPLITTER << std::endl;
}

void ScanHandler::TCPSweep(std::vector<int> targetPorts, bool isVerbose)
{
    int finalThreads = this->maxThreads;

    // Divide hosts across threads

    std::vector<std::vector<std::string>> threadHosts(finalThreads);
    for (size_t i = 0; i < this->hostNames.size(); ++i) {
        threadHosts[i % finalThreads].push_back(this->hostNames[i]);
    }

    // Divide ports across threads
    std::vector<std::vector<int>> threadPorts(finalThreads);
    for (size_t i = 0; i < targetPorts.size(); ++i) {
        threadPorts[i % finalThreads].push_back(targetPorts[i]);
    }

    std::vector<std::future<std::vector<NetworkNode>>> futures;
    struct addrinfo hints = getWSA(); 
    ScanMonitor scanVals = this->scanMonitor.load();
    scanVals.hostsDone = 0;
    scanVals.portsDone = 0;
    scanVals.threadsEnabled = true;
    this->scanMonitor.store(scanVals);

    std::thread consoleThread(handleConsole, std::ref(this->scanMonitor));

    // Divide work across threads according to largest load
    if (this->hostNames.size() > maxThreads && targetPorts.size() > maxThreads)
    {
        for (size_t i = 0; i < finalThreads; ++i) {
            futures.push_back(
                std::async(std::launch::async, scanHosts, threadHosts[i], threadPorts[i], hints, std::ref(this->scanMonitor))
            );
        }
    }
    else if (this->hostNames.size() > maxThreads && targetPorts.size() < maxThreads)
    {
        for (size_t i = 0; i < finalThreads; ++i) {
            futures.push_back(
                std::async(std::launch::async, scanHosts, threadHosts[i], targetPorts, hints, std::ref(this->scanMonitor))
            );
        }
    }
    else if (this->hostNames.size() < maxThreads && targetPorts.size() > maxThreads)
    {
        for (size_t i = 0; i < finalThreads; ++i) {
            futures.push_back(
                std::async(std::launch::async, scanHosts, this->hostNames, threadPorts[i], hints, std::ref(this->scanMonitor))
            );
        }
    }
    else
    {
        // if we only have small number of hosts with a small number of ports then just run one thread
        futures.push_back(
            std::async(std::launch::async, scanHosts, this->hostNames, targetPorts, hints, std::ref(this->scanMonitor))
        );
    }

    for (auto& scanFuture : futures)
    {
        std::vector<NetworkNode> scanResults = scanFuture.get();
        for (NetworkNode &testedNode : scanResults)
        {
            for (NetworkNode &targetHost : this->targetHosts)
            {
                if (testedNode.getName() == targetHost.getName())
                {
                    targetHost.appendPorts(testedNode.getRequestedPorts());
                    targetHost.setActive();
                }
            }
        }
    }
    scanVals = scanMonitor.load();
    scanVals.threadsEnabled = false;
    scanMonitor.store(scanVals);
    if (consoleThread.joinable())
    {
        consoleThread.join();
    }
    windowsCleanup();
}

std::vector<NetworkNode> ScanHandler::getTargetHosts()
{
    return this->targetHosts;
}

std::vector<std::string> ScanHandler::getHostnames()
{
    return this->hostNames;
}
