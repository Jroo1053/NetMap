//
// NetMap - C++ Network Scanner
// ---------------------------
// ScanHandler:
// Deals with all major networking proccesses related to scanning. (Header File)
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
#pragma once
#include <vector>
#include <string>
#include <atomic>
#include <map>
#pragma comment (lib, "Mswsock.lib")
#include <WinSock2.h>
#pragma comment(lib, "ws2_32")

class NetworkPort {
public:
	NetworkPort(int portNumber);
	NetworkPort(int portNumber, bool portStatus, int portReason);
public:
	bool getStatus();
	int getNumber();
	bool operator<(const NetworkPort& netPort);
	bool operator<=(const NetworkPort& netPort);
	bool operator>(const NetworkPort& netPort);
	bool operator>=(const NetworkPort& netPort);
	std::string getExpectedService(std::map<int,std::string> serviceMap);
private:
	int portNumber;
	std::string serviceName;
	int portReason;
	bool portStatus;
};

class NetworkNode
{
public:
	NetworkNode(std::string hostAddress, std::vector<NetworkPort> hostPorts);
	NetworkNode(std::string hostAddress, std::vector<int> targetPorts,bool pingStatus);
	NetworkNode(std::string hostAddress, bool pingResult);
public:
	std::string getName();
	std::vector<NetworkPort> getPorts();
	void appendPort(NetworkPort newPort);
	void appendPorts(std::vector<NetworkPort> newPorts);
	void setPorts(std::vector<NetworkPort> newPorts);
	void setActive();
	bool getActive();
	std::vector<NetworkPort> getActivePorts();
	std::vector<NetworkPort> getRequestedPorts();
	void setMac(std::string macAddr);
	std::string getMac();
private: 
	std::vector<NetworkPort> portResults{};
	std::vector<NetworkPort> requestedPorts{};
	std::string networkAddress{};
	bool isActive = false;
	std::string macAddr{};
};

struct tempResult {
	std::string hostAddress{};
	bool hostStatus = false;
	std::string macAddr{};
};

struct ScanMonitor
{
	int hostsDone = 0;
	int portsDone = 0;
	bool threadsEnabled = true;
	int networkDelay = 0;
};


class ScanHandler
{
public:
	ScanHandler(std::vector<std::string> targetAddresses, std::vector<int>targetPorts,int maxThreads, int networkDelay);
public:
	void pingSweep(bool isVerbose);
	void printResults(bool isVerbose);
	void TCPSweep(std::vector<int> targetPorts, bool isVerbose);
	std::vector<NetworkNode> getTargetHosts();
	std::vector<std::string> getHostnames();
	std::vector<NetworkNode> targetHosts;
private:
	std::vector<NetworkPort> targetPorts;
	int maxThreads;
	int networkDelay;
	std::atomic<ScanMonitor> scanMonitor;
	std::vector<std::string> hostNames;
	struct addrinfo scanHints;
	std::map<int, std::string> serviceMap;

};

std::map<int, std::string> loadKnownServices();
