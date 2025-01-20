//
// NetMap - C++ Network Scanner
//
//MIT License
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
#include "CLIHandler.h"
#include "Validators.h"
#include "ScanHandler.h"
#include <iostream>
#include <chrono>
#include <vector>
#include <format>
#include <thread>

char const constexpr* const HELP_FLAG = "help";
char const constexpr* const VERBOSE_FLAG = "verbose";
char const constexpr* const FAST_FLAG = "fast-mode";
char const constexpr* const TARGET_FLAG = "target";
char const constexpr* const PORT_FLAG = "port";
char const constexpr* const DELAY_FLAG = "delay";
char const constexpr* const THREADS_FLAG = "net-threads";

static void handlePingSweep(bool isVerbose, ScanHandler& scanHandle)
{
    std::cout << SPLITTER << std::endl;
    std::cout << "Starting ping sweep" << std::endl;
    auto pingStart = std::chrono::high_resolution_clock::now();

    scanHandle.pingSweep(isVerbose);

    auto pingComplete = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(pingComplete - pingStart);
    std::cout << std::format("Pinged {} hosts in {}", scanHandle.getHostnames().size(), duration) << std::endl;
}

static void handleTCPSweep(bool isVerbose, ScanHandler& scanHandle, std::vector<int> portNumbers)
{
    std::cout << "Running TCP scan against active hosts" << std::endl;
    std::cout << SPLITTER << std::endl;

    auto tcpStart = std::chrono::high_resolution_clock::now();

    scanHandle.TCPSweep(portNumbers, isVerbose);

    auto tcpComplete = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(tcpComplete - tcpStart);

    std::cout << std::format("Scanned {} hosts in {}", scanHandle.getHostnames().size(), duration) << std::endl;


    // quick fix for verbose output bieng useless if too many ports are specified.
    if (isVerbose && portNumbers.size() < 64)
    {
        scanHandle.printResults(isVerbose);
    }
    else
    {
        scanHandle.printResults(false);
    }
}

std::vector<CLIArg> argSetup()
{
    int defaultThreads = std::thread::hardware_concurrency();

    // setup default ports
    // not the smartest way but it works sort of
    std::map<int, std::string> allServices = loadKnownServices();
    std::vector<int> defaultPorts;

    for (auto service : allServices)
    {
        if (service.first < 3500)
        {
            defaultPorts.push_back(
                service.first
            );
        }
    }

    return std::vector<CLIArg>{
    CLIArg(HELP_FLAG,false,true),
    CLIArg(VERBOSE_FLAG,false),
    CLIArg(FAST_FLAG,false),
    CLIArg(TARGET_FLAG,true,validateTarget),
    CLIArg(PORT_FLAG,false,validatePort,defaultPorts),
    CLIArg(THREADS_FLAG,false,validateThreads, defaultThreads),
    CLIArg(DELAY_FLAG,false,validateDelay,0)
    };
}

int main(int argc, char* argv[])
{
    // Run init checks (fail fast)
    if (argc < 2)
    {
        displayHelp(false);
        exit(0);
    }
    // some host resolution stuff requires a WSAStartup call first
    // quit if this fails 
    if (!windowsInit()) {
        std:: cout << "Failed to start Windows socket, Exiting!" << std::endl;
        windowsCleanup();
        exit(1);
    }
   
    CLIHandler argHandler = CLIHandler(argSetup());
    displayHeader();

    try{
        if (!argHandler.parseArgs(argc, argv))
        {
            displayHelp(true);
            windowsCleanup();
            exit(0);
        }

        // grab parsed args
        bool isVerbose = argHandler.getHandledArg(VERBOSE_FLAG).size() > 0;
        bool isFastMode = argHandler.getHandledArg(FAST_FLAG).size() > 0;
        std::vector<CLIArg> targetHosts = argHandler.getHandledArg(TARGET_FLAG);
        std::vector<CLIArg> targetPorts = argHandler.getHandledArg(PORT_FLAG);
        int netDelay = argHandler.getHandledArg(DELAY_FLAG)[0].getValueInt();
        int netThreads = argHandler.getHandledArg(THREADS_FLAG)[0].getValueInt();

        if (isVerbose)
        {
            std::cout << "Started in verbose mode" << std::endl;
        }
        if (isFastMode)
        {
            std::cout << "Running in fast mode, skipping ping sweep" << std::endl;
        }

        std::vector<std::string> hostAddresses{};
        for (CLIArg host : targetHosts)
        {
            std::vector<std::string> expandedHost = expandNetwork(host.getValueString());
            hostAddresses.insert(hostAddresses.end(), expandedHost.begin(), expandedHost.end());
        }

        if (hostAddresses.size() == 0)
        {
            std::cout << "Failed to resolve any valid hosts from provided targets" << std::endl;
            exit(0);
        }

        std::vector<int> portNumbers{};
        for (CLIArg port : targetPorts)
        {
            try
            {
                std::vector<int> portVal = std::get<std::vector<int>>(port.getValue());
                portNumbers.insert(portNumbers.end(), portVal.begin(), portVal.end());
            }
            catch (const std::exception&)
            {
                portNumbers.push_back(port.getValueInt());
            }
        }

        if (isVerbose)
        {
            std::cout << std::format("Running with {} threads", netThreads) << std::endl;
            std::cout << std::format("Using a {}ms delay", netDelay) << std::endl;
        }

        ScanHandler scanHandle(hostAddresses, portNumbers, netThreads,netDelay);
       
        std::cout << "Targeting: " << hostAddresses.size() << " hosts" << std::endl;
        std::cout << "Targeting: " << portNumbers.size() << " ports" << std::endl;

        if (!isFastMode)
        {
            handlePingSweep(isVerbose, scanHandle);
        }

        handleTCPSweep(isVerbose, scanHandle, portNumbers);
 
        windowsCleanup();
        exit(0);
    }
    catch (const std::exception& x)
    {
        windowsCleanup();
        std::cerr << x.what() << "\n";
        displayHelp(false);
        exit(1);
    }
}