//
// NetMap - C++ Network Scanner
//
//MIT License
//
//Copyright(c)[2024][Elyse Frary]
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files(the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions :
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.


#include "NetHandler.h"
#include "utils.h"
#include <vector>
#include <string>
#include <thread>
#include <future>
#include <iostream>
#include <chrono>
#include <conio.h>
#include <atomic>
#include <format>
#include <stdexcept>
#pragma comment (lib, "Mswsock.lib")
#include <WinSock2.h>
#pragma comment(lib, "ws2_32")
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include<IcmpAPI.h>
#pragma comment(lib, "iphlpapi.lib")

constexpr int DATA_SIZE = 48;
constexpr int ICMP_ECHO_TIMEOUT = 1000;
constexpr int ICMP_ECHO_MAX_TRIES = 3;

class NetException : public std::runtime_error {
public:
	NetException(const std::string& message)
		: std::runtime_error(message) {}
};

/// <summary>
/// multithreaded ICMP sweep 
/// </summary>
/// <param name="targetHosts">list of hosts</param>
/// <param name="delay">delay between each HOST</param>
/// <param name="networkThreads">number of threads to use</param>
/// <returns></returns>
std::vector<NetResult> NetHandler::pingSweep(std::vector<std::string> targetHosts,int delay, int networkThreads)
{
	std::vector<NetResult> pingResults;
	std::vector<std::future<std::vector<NetResult>>> futures;
	std::atomic<int> hostsDone(0);
	std::atomic<bool> shouldRun(true);


	//launch interactive console
	std::thread consoleThread(handleConsole, std::ref(hostsDone), std::ref(shouldRun)); 

	if (networkThreads == 0)
	{
		std::cout << "Failed to get CPU core count, using a single thread";
		networkThreads = 1;
	}

	size_t pingRange = (targetHosts.size() + networkThreads - 1) / networkThreads;

	for (int i = 0; i < networkThreads; i++)
	{
		size_t start = 0;
		size_t end = 0;
		if (i > 0)
		{
			start = i * pingRange;
			end = min(start + pingRange, targetHosts.size()) - 1;
		}
		else
		{
			end = min(pingRange, targetHosts.size()) - 1;
		}

		if (start >= targetHosts.size()) {
			break;
		}

		// Get hosts for this thread
		std::vector<std::string> threadHosts = std::vector<std::string>(
			targetHosts.begin() + start, targetHosts.begin() + end + 1
		);
		futures.push_back(std::async(std::launch::async,pingHosts,threadHosts,delay,std::ref(hostsDone),std::ref(shouldRun)));
	}

	for (auto& pingFuture : futures)
	{
		std::vector<NetResult> futureResult = pingFuture.get();
		pingResults.insert(pingResults.end(), futureResult.begin(), futureResult.end());
		

		// this is required otherwise console will run forever.
		if (pingResults.size() == targetHosts.size())
		{
			shouldRun.store(false);
			consoleThread.join();
		}
	}

	if (consoleThread.joinable()) {
		consoleThread.join();
	}
	windowsCleanup();
	return pingResults;
}
/// <summary>
/// wrapper func for WSAStartup
/// makes init cleaner
/// </summary>
/// <returns></returns>
static struct addrinfo wsaStartup()
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

/// <summary>
/// Launch a ICMP request and get result
/// will try multiple times
/// </summary
/// <param name="targetHost">host to ping</param>
/// <returns>NetResult containing ping outcome</returns>
static NetResult pingHost(std::string targetHost)
{
	int currentAttempts = 0;
	NetResult pingResult;
	pingResult.hostAddress = targetHost;
	pingResult.ICMPStatus = false;

	sockaddr_in addr = {};
	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;

	HANDLE ICMPFile;
	ICMPFile = IcmpCreateFile();

	void* replyBuffer = nullptr;

	if (inet_pton(AF_INET, targetHost.c_str(), &addr.sin_addr) != 1)
	{
		throw NetException("Failed to convert address");
	}

	unsigned long IPAddr = addr.sin_addr.s_addr;

	while (currentAttempts < ICMP_ECHO_MAX_TRIES)
	{
		// not sure if there is a reason to do this or not  
		std::string sendData = randomString(DATA_SIZE);
		if (IPAddr != INADDR_NONE)
		{
	
			DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sendData.size();
			replyBuffer = malloc(replySize);

			if (replyBuffer == NULL)
			{
				throw NetException("Failed to allocate reply memory\n");
			}

			DWORD replyCount = IcmpSendEcho(ICMPFile, IPAddr, (void*)sendData.c_str(), sendData.size(),
				NULL, replyBuffer, replySize, ICMP_ECHO_TIMEOUT);
			PICMP_ECHO_REPLY echoReply = (PICMP_ECHO_REPLY)replyBuffer;
			
			if (replyCount != 0)
			{
				if (echoReply->Status == IP_SUCCESS)
				{
					pingResult.ICMPStatus = true;
				}
				else if (echoReply->Status == IP_DEST_HOST_UNREACHABLE) {
					pingResult.ICMPStatus = false;
				}
				else
				{
					// call out any "odd" error codes
					printf("Got non standard error: %d for host: %s\\n", echoReply->Status, targetHost.c_str());
				}
				free(replyBuffer);
				return pingResult;
			}
			int errorCode = GetLastError();
			// dependent on the number of threads we are spamming the network
			// assume that failures will occur, so only note them if they occur too often.
			if (errorCode == IP_GENERAL_FAILURE && currentAttempts > 1)
			{
				printf("Failed to ping host %s, got general failure\n", targetHost.c_str());

			}
			currentAttempts++;
		}
	}

	if (replyBuffer != nullptr)
	{
		free(replyBuffer);
	}

	pingResult.ICMPStatus = false;
	return pingResult;
}
/// <summary>
/// util func to ping multiple hosts called by the sweep
/// needed to send atomics
/// </summary>
/// <param name="targetHosts">hosts to ping</param>
/// <param name="delay">delay between each host</param>
/// <param name="hostsDone">atomic of hosts with an attempt</param>
/// <param name="shouldRun">atomic to kill execution early</param>
/// <returns>vector<NetResult> of icmp outcomes</returns>
static std::vector<NetResult> pingHosts(std::vector<std::string> targetHosts, int delay, std::atomic<int>& hostsDone, std::atomic<bool>& shouldRun)
{
	std::vector<NetResult> pingResults;
	for (const auto& host : targetHosts)
	{
		if (shouldRun.load() == true)
		{
			pingResults.push_back(pingHost(host));
			std::this_thread::sleep_for(std::chrono::milliseconds(delay));
			hostsDone.store(hostsDone.load() + 1);
		}
		else
		{
			return pingResults;
		}
	}
	return pingResults;
}

std::vector<PortResult> portScan(std::string targetHost, std::vector<int> targetPorts,
	addrinfo hints, std::atomic<bool>& stopFlag, std::atomic<int>& portsDone)
{
	SOCKET connectionSock = INVALID_SOCKET;
	struct addrinfo* result = NULL,
		* ptr = NULL;

	std::vector<PortResult> portResults;


	for (auto& targetPort : targetPorts)
	{
		if (stopFlag.load())
		{
			return portResults;
		}
		std::string portString = std::to_string(targetPort);
		if (getaddrinfo(targetHost.c_str(), portString.c_str(), &hints, &result) != 0)
		{
			freeaddrinfo(result);
			printf("Failed to resolve address %s, got error: %d\n",
				targetHost.c_str(), WSAGetLastError());
			WSACleanup();
			throw NetException("Host resolution failed\n");
		}

		ptr = result;
		connectionSock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (connectionSock == INVALID_SOCKET) {
			freeaddrinfo(result);
			printf("Error at socket(): %d\n", WSAGetLastError());
			WSACleanup();
			throw NetException("Failed to create socket");
		}


		PortResult portRes;
		int connectionResult = connect(connectionSock, ptr->ai_addr, (int)ptr->ai_addrlen);

		portRes.portNumber = targetPort;

		if (connectionResult == SOCKET_ERROR)
		{
			portRes.closeReason = WSAGetLastError();
			portRes.portOpen = false;
		}
		else
		{
			portRes.portOpen = true;
		}
		closesocket(connectionSock);
		freeaddrinfo(result);
		portResults.push_back(portRes);
		portsDone.store(portsDone.load() + 1);
	}
	freeaddrinfo(result);
	return portResults;

}

NetResult NetHandler::scanHost(std::string targetHost, std::vector<int> targetPorts, int networkThreads)
{
	NetResult netRes;
	addrinfo hints = wsaStartup();
	netRes.hostAddress = targetHost;

	std::vector<std::future<std::vector<PortResult>>> futures;


	if (networkThreads == 0) {
		std::cout << "Failed to get max thread count, defaulting to 1";
		networkThreads = 1;
	}

	size_t portCount = targetPorts.size();
	size_t rangeSize = (portCount + networkThreads - 1) / networkThreads;

	std::atomic<bool> consoleShouldRun(true);
	std::atomic<bool> stopFlag(false);
	std::atomic<int> portsDone(0);


	for (size_t i = 0; i < networkThreads; i++)
	{
		size_t start = i * rangeSize;
		size_t end = min(start + rangeSize, portCount) - 1;
		if (start >= portCount) {
			break;
		}
		std::vector<int> threadPorts = std::vector<int>(targetPorts.begin() + start,
			targetPorts.begin() + end + 1);

		futures.push_back(
			std::async(std::launch::async, portScan, targetHost, threadPorts, hints,
				std::ref(stopFlag), std::ref(portsDone))
		);

	}

	for (auto& portFuture : futures)
	{
		std::vector<PortResult> futureResult = portFuture.get();
		netRes.portResults.insert(netRes.portResults.end(), futureResult.begin(), futureResult.end());
		if (netRes.portResults.size() == portCount)
		{
			consoleShouldRun.store(false);
		}
	}

	WSACleanup();
	return netRes;

}



std::vector<NetResult> NetHandler::TCPSweep(std::vector<std::string> targetHosts,
	std::vector<int> targetPorts, int networkThreads)
{
	std::vector<NetResult> scanResults;
	for (const auto& targetHost : targetHosts)
	{
		scanResults.push_back(this->scanHost(targetHost, targetPorts,networkThreads));
	}
	return scanResults;
}

int handleConsole(std::atomic<int>& hostsDone, std::atomic<bool>& shouldRun)
{
	std::cout << "Press q to exit, s for status\n";
	while (true)
	{
		if (!shouldRun.load())
		{
			return 0;
		}
		// this works for some reason idk
		int charInput = _kbhit() ? _getch() : -1;

		if (charInput == 'q')
		{
			std::cout << "Quitting Early!\n";
			shouldRun.store(false);
			return 0;
		}
		else if (charInput == 's')
		{
			printf("Completed %d hosts\n",hostsDone.load());
		}
		else if (charInput > 0)
		{
			std::cout << "Press q to exit, press s for status\n";
		}

	}
}
