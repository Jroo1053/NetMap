#pragma once
#include <vector>
#include <string>
#include <atomic>

#pragma comment (lib, "Mswsock.lib")
#include <WinSock2.h>
#pragma comment(lib, "ws2_32")
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include<IcmpAPI.h>
#pragma comment(lib, "iphlpapi.lib")

class PortResult
{
public:
	int portNumber = 0;
	bool portOpen = false;
	int closeReason = 0;
};


class NetResult
{
public:
	bool ICMPStatus = false;
	std::string hostAddress{};
	std::vector<PortResult> portResults{};
};



class NetHandler
{
public:
	std::vector<NetResult> pingSweep(std::vector<std::string> targetHosts, int delay, int maxThreads);
	NetResult scanHost(std::string targetHost, std::vector<int> targetPorts, int networkThreads);
	std::vector<NetResult> TCPSweep(std::vector<std::string> targetHosts, std::vector<int> targetPorts, int networkThreads);
};

static NetResult pingHost(std::string targetHost);

static std::vector<NetResult> pingHosts(std::vector<std::string> targetHosts, int delay,std::atomic<int>& hostsDone, std::atomic<bool>& shouldRun );

std::vector<PortResult> portScan(std::string targetHost, std::vector<int> targetPorts, addrinfo hints, std::atomic<bool>& stopFlag, std::atomic<int>& portsDone);


int handleConsole(std::atomic<int>& hostsDone, std::atomic<bool>& shouldRun);