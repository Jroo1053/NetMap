// ---------------------------
// Utils:
// Misc functions to make some stuff a little cleaner (Header File)
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
#include "utils.h"
#pragma comment (lib, "Mswsock.lib")
#include <WinSock2.h>
#pragma comment(lib, "ws2_32")
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include<IcmpAPI.h>
#pragma comment(lib, "iphlpapi.lib")
#include<stdexcept>
#include <random>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

void displayHelp(bool toggleLong) {
	if (toggleLong == true) {
		printf("%s - (%s)\n%s\n%s\n%s\n%s\n", TITLE, VERSION,
			SPLITTER, REPO_LINK, SPLITTER, LONG_HELP);
		return;
	}
	printf("%s : (%s) %s\n", TITLE, VERSION, SHORT_HELP);
}

void displayHeader()
{
	printf("%s (%s)\n%s\n", TITLE, VERSION, SPLITTER);
}

bool windowsInit()
{
	WSADATA WSAData;
	if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
	{
		return false;
	}
	return true;
}

void windowsCleanup() { WSACleanup(); }

std::string randomString(int size)
{
	static auto& chrs = "0123456789"
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	thread_local static std::mt19937 rg{ std::random_device{}() };
	thread_local static std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

	std::string s;

	s.reserve(size);

	while (size--)
		s += chrs[pick(rg)];

	return s;
}

class UtilException : public std::runtime_error {
public:
	UtilException(const std::string& message)
		: std::runtime_error(message) {}
};

/// <summary>
/// Expand a CIDR expression to a full list of addresses.
/// </summary>
/// <param name="networkNotation"></param>
/// <returns>vector<string> of IP addresses</returns>
std::vector<std::string> expandCIDR(std::string networkNotation ) {
	uint8_t firstByte, secondByte, thirdByte, fourthByte, notation = 0;
	std::vector<std::string> allHosts;


	if (sscanf_s(networkNotation.c_str(), "%hhu.%hhu.%hhu.%hhu/%hhu",
		&firstByte, &secondByte, &thirdByte, &fourthByte, &notation) < 4) {
		throw UtilException("Provided with invalid IP");
	}
	if (notation > 32) {
		throw UtilException("CIDR mask out of range");
	}
	if (notation == 32 || notation == NULL) {
		// skip maths and just return address
		char stringAddr[128];
		snprintf(stringAddr, 128, "%d.%d.%d.%d", firstByte, secondByte, thirdByte, fourthByte);

		allHosts.push_back(std::string(stringAddr));
		return allHosts;
	}

	// Calc the first IP and last IP
	uint32_t ip = (firstByte << 24UL) |
		(secondByte << 16UL) |
		(thirdByte << 8UL) |
		(fourthByte);
	uint32_t mask = (0xFFFFFFFFUL << (32 - notation)) & 0xFFFFFFFFUL;
	uint32_t firstIp = ip & mask;
	uint32_t lastIp = firstIp | ~mask;

	for (size_t i = firstIp + 1; i < lastIp; i++)
	{
		char finalString[256];
		int addressFlipped = htonl(i);
		inet_ntop(
			AF_INET, &addressFlipped, finalString, 256
		);
		allHosts.push_back(finalString);
	}
	return allHosts;
}

/// <summary>
/// Perform DNS resolution against a provided hostname
/// </summary>
/// <param name="hostname">hostname to resolve</param>
/// <returns>IP address of host as string</returns>
std::string resolveHostname(std::string& hostname)
{
	struct addrinfo hints = {};
	struct addrinfo* result = nullptr;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	int res = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);

	for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next)
	{
		char addressBuffer[INET6_ADDRSTRLEN];
		if (rp->ai_family == AF_INET)
		{
			struct sockaddr_in* addr = (struct sockaddr_in*)rp->ai_addr;
			return inet_ntop(AF_INET, &addr->sin_addr, addressBuffer, sizeof(addressBuffer));
		}
	}

	return std::string{};
}

/// <summary>
/// Expand a network from a given host string, has multiple outcomes:
/// 1. If host is CIDR notated return all possible adresses
/// 2. If host is an IP return the IP
/// 3. if host is a hostname perform DNS resolution.
/// </summary>
/// <param name="hostString"></param>
/// <returns>vector<string> of final addresses)</returns>
std::vector<std::string> expandNetwork(std::string hostString)
{
	std::vector<std::string> allHosts{};
	struct in_addr addr; 
	if (inet_pton(AF_INET,hostString.c_str(),&addr) == 1)
	{
		// should be a basic ip with no CIDR
		allHosts.push_back(hostString);
	}
	else
	{
		std::regex CIDRRegex(R"(^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$)");
		std::smatch hostMatch;
		if (std::regex_match(hostString, hostMatch, CIDRRegex))
		{
			allHosts = expandCIDR(hostString);
		}
		else
		{
			// asume that this is a hostname
			std::string hostResult = resolveHostname(hostString);
			if (hostResult.size() > 0)
			{
				allHosts.push_back(hostResult);
			}
		}
	}
	return allHosts;
}