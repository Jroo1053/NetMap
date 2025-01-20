//
// NetMap - C++ Network Scanner
// ---------------------------
// Validators:
// Basic functions to check if values are within reasoanble ranges.
// Called whenever CLIArg.setValue() is called and specified in CLIArg constructor.
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
#include "Validators.h"
#include "CLIHandler.h"
#include "utils.h"
#include <string>
#include <stdexcept>
#include <format>


constexpr int PORT_LIMIT = 65355;
constexpr int HOST_LEN_MAX = 253;
constexpr int MAX_THREADS = 1024;
constexpr int MAX_DELAY = 50000;
constexpr int MIN_DELAY = 30;

class ArgException : public std::invalid_argument {
public:
	ArgException(const std::string& message)
		: std::invalid_argument(message) {}
};

/// <summary>
/// Check if TCP port is within range and is actually a number.
/// </summary>
/// <param name="portValue">Value to check</param>
/// <returns>bool if port is correct</returns>
struct validationResult validatePort(CLIArg::ArgValue portValue)
{
	std::string portValueString = std::get<std::string>(portValue);
	try
	{
		int port = std::stoi(portValueString);
		if (port > PORT_LIMIT || port <= 0)
		{
			return { false, std::format("Provided port: {} outside of valid range\n", portValueString) };
		}
		return { true, "" };
	}
	catch (const std::exception&)
	{
		return { false, std::format("Provided port: {} not valid\n", portValueString) };
	}
	return { true, "" };

}
/// <summary>
/// Checks if a hostname is valid according to RFC 952/1123
/// </summary>
/// <param name="hostValue"></param>
/// <returns></returns>
struct validationResult validateTarget(CLIArg::ArgValue hostValue)
{
	std::string hostValueString = std::get<std::string>(hostValue);
	if (hostValueString.size() > HOST_LEN_MAX)
	{
		return { false,std::format(
			"Provided target: '{}' exceeds host length maximum\n", hostValueString) };
	}

	// Regex could be used here but its harder to read than simple approaches
	if (hostValueString.front() == '-' || hostValueString.back() == '-')
	{
		return { false,std::format(
			"Provided target: '{}' has hyphens at end or start\n", hostValueString)};
	}
	for (char c : hostValueString)
	{
		if (!std::isalpha(c) && c != '-' && c != '.')
		{

		}
	}
	return { true, "" };
}

/// <summary>
/// Check if the threads are within a sane range.
/// </summary>
/// <param name="threadsValue">requested thread count</param>
/// <returns>true if threads within range and is an int</returns>
struct validationResult validateThreads(CLIArg::ArgValue threadsValue) {
	std::string threadsString = std::get<std::string>(threadsValue);
	try
	{
		int requestedThreads = std::stoi(threadsString);
		if (requestedThreads > MAX_THREADS || requestedThreads <= 0)
		{
			return { false,std::format(
				"Requested threads : '{}' out of range\n", requestedThreads) };
		}
		return { true, "" };
	}
	catch (const std::exception&)
	{
		return { false,std::format("Provided thread request: '{}' not valid\n", threadsString)};
	}
	return { true, "" };
}

/// <summary>
/// Check if the delay time is within valid range
/// </summary>
/// <param name="threadsValue">requested delay time</param>
/// <returns>true if delay within range and is an int</returns>
struct validationResult validateDelay(CLIArg::ArgValue delayValue)
{
	std::string delayString = std::get<std::string>(delayValue);
	try
	{
		int requestedDelay = std::stoi(delayString);
		if (requestedDelay > MAX_DELAY || requestedDelay < MIN_DELAY)
		{
			return { false,	std::format("Requested delay '{}' is out of range\n", requestedDelay) };
		}
	}
	catch (const std::exception&)
	{
		return { false, std::format("Requested delay '{}' is not valid\n", delayString) };
	}
	return { true, "" };
}

