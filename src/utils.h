//
// NetMap - C++ Network Scanner
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

#pragma once
#include <vector>
#include <string>
#include <time.h>
#include <regex>


// Hardcoded values for intro text and others.
constexpr auto TITLE = "NetMap";
constexpr auto VERSION = "v0.1";
constexpr auto SPLITTER = "------------------------";
constexpr auto VERBOSE_INTRO = "Started in verbose mode";
constexpr auto SHORT_HELP = "Usage: map [-h help] [-t target] [-p ports] [-n net-threads] [-d delay] [-f fast-mode]  [-v verbose]";
constexpr auto REPO_LINK = "https://github.com/jroo1053/NetMap";
constexpr auto LONG_HELP = "TCP network scanner.\nOptions: -t (Required) hosts to target, may use CIDR notation or hostname\
\n-p ports to target\n-n number of threads to use\n-d delay between each host in ms\n-f skip ping scan\n-v toggle verbose output\
\n-h print this message";

bool windowsInit();

void windowsCleanup();

void displayHelp(bool longOutput);

void displayHeader();


std::string randomString(int size);

std::string resolveHostname(std::string& hostname);

std::vector<std::string> expandNetwork(std::string networkNotation);