//
// NetMap - C++ Network Scanner
// ---------------------------
// CLI Handler:
// Manages command line args in a sensible-ish way (Header file)
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


#include <string>
#include <variant>
#include <vector>
#include <functional>
#include <tuple>
#include <stdexcept>
#pragma once

class CLIArg
{
public:
	using ArgValue = std::variant<int, double, std::string, bool, std::vector<int>>;
public:
	CLIArg(std::string longFlag, bool isRequired,std::function< struct validationResult(CLIArg::ArgValue)> validator, std::vector<int> defaultValue);
	CLIArg(std::string longFlag, bool isRequired,std::function< struct validationResult(CLIArg::ArgValue)> validator, int defaultValue);
	CLIArg(std::string longFlag, bool isRequired,std::function<struct validationResult(CLIArg::ArgValue)> validator);
	CLIArg(std::string longFlag, bool isRequired, int isHelp);
	CLIArg(std::string longFlag, bool isRequired);
	CLIArg() = default;
private:
	ArgValue value;
	//std::function<std::tuple<bool,std::string>> validator;
	//std::function<struct validationResult(CLIArg::ArgValue)> validator;
	std::function<struct validationResult(ArgValue)> validator;
	std::string longFlag{};
	char shortFlag{};
	bool isRequired = false;
	bool isValueNeeded = false;
	bool isDefaultable = false;
	bool isVector = false;
	bool isHelp = false;
public:
	bool isArgRequired();
	bool isValueExpected();
	bool isArgDefaultable();
	bool isVectorPossible();
	bool isArgHelp();
	std::string getLongFlag();
	char getShortFlag();
	const ArgValue& getValue();
	int getValueInt();
	std::string getValueString();
	template <typename T>
	void setValue(T&& val);
};

// basic struct to keep track of the presence of the required arguments
struct RequiredArgTracker
{
	std::string name;
	bool isPresent = false;
};

class CLIHandler
{
public:
	CLIHandler(std::vector<CLIArg> desiredArgs);
	bool getDefinedArg(std::string longFlag, CLIArg* argBuffer);
	std::vector<CLIArg> getHandledArg(std::string longFlag);
private:
	std::vector<CLIArg> definedArgs;
	std::vector<CLIArg> handledArgs;
	std::vector<RequiredArgTracker> argTracker;

public:
	bool parseArgs(int argc, char* argv[]);
};

template<typename T>
inline void CLIArg::setValue(T&& val)
{
	validationResult validateResult = validator(val);
	if (!validateResult.outcome)
	{
		throw std::invalid_argument(validateResult.outcomeMessage);
	}
	this->value = val;
}
