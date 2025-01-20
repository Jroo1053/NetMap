//
// NetMap - C++ Network Scanner
// ---------------------------
// CLI Handler:
// Manages command line args in a sensible-ish way
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
#include "CLIHandler.h"
#include "Validators.h"
#include <stdexcept>
#include <vector>
#include <string>
#include <format>
#include<functional>


class ArgException : public std::invalid_argument {
public:
	ArgException(const std::string& message)
		: std::invalid_argument(message) {}
};

/// <summary>
/// helper func for simple args that don't require validation, i.e toggle verbose
/// makes downstream implementation easier as we can always assume that a validation func is
/// present.
/// </summary>
/// <param name="testVal">'value' to test</param>
/// <returns>always true</returns>
validationResult setTrueValidator(const CLIArg::ArgValue& testVal)
{
	return { true, "" };
}

// arg with a validator and a default value of int
CLIArg::CLIArg(std::string longFlag, bool isRequired, std::function<struct validationResult(CLIArg::ArgValue)> validator, int defaultValue)
{
	this->longFlag = longFlag;
	this->shortFlag = longFlag[0];
	this->isRequired = isRequired;
	this->isValueNeeded = true;
	// skip validation assuming that a hard-coded value makes sense
	// the validator is still called when the value is not left at default
	this->value = defaultValue;
	this->validator = validator;
	this->isDefaultable = true;
}

// arg with a validator and a defualt value of vector<int>
CLIArg::CLIArg(std::string longFlag, bool isRequired, std::function<struct validationResult(CLIArg::ArgValue)> validator, std::vector<int> defaultValue)
{
	this->longFlag = longFlag;
	this->shortFlag = longFlag[0];
	this->isRequired = isRequired;
	this->isValueNeeded = true;
	// skip validation assuming that a hard-coded value makes sense
	// the validator is still called when the value is not left at default
	this->value = defaultValue;
	this->validator = validator;
	this->isDefaultable = true;
	this->isVector = true;
}

// arg with a validator but no defualt
CLIArg::CLIArg(std::string longFlag, bool isRequired, std::function<struct validationResult(CLIArg::ArgValue)> validator)
{
	this->longFlag = longFlag;
	this->shortFlag = longFlag[0];
	this-> isRequired = isRequired;
	this->validator = validator;
	this->isValueNeeded = true;
}

// Special arg for help flags that will be called before final validation
// int is used rather than bool to workaround functions bieng convereted to bool, which breaks other constructors
CLIArg::CLIArg(std::string longFlag, bool isRequired, int isHelp)
{
	this->longFlag = longFlag;
	this->shortFlag = longFlag[0];
	this->isHelp = true;
	this->validator = setTrueValidator;
}

// basic arg with no value
// validator always returns true for simplicity
CLIArg::CLIArg(std::string longFlag, bool isRequired)
{
		this->longFlag = longFlag;
		this->shortFlag = longFlag[0];
		this->validator = setTrueValidator;
		this->isRequired = isRequired;
}

bool CLIArg::isArgRequired()
{
	return this->isRequired;
}

bool CLIArg::isValueExpected()
{
	return this->isValueNeeded;
}

bool CLIArg::isArgDefaultable()
{
	return this->isDefaultable;
}

bool CLIArg::isVectorPossible()
{
	return this->isVector;
}

bool CLIArg::isArgHelp()
{
	return this->isHelp;
}

std::string CLIArg::getLongFlag()
{
	return this->longFlag;
}

char CLIArg::getShortFlag()
{
	return this->shortFlag;
}

/// <summary>
/// Get the current arg value as a variant.
/// </summary>
/// <returns>variant containg arg value</returns>
const CLIArg::ArgValue& CLIArg::getValue()
{
	return this->value;
}

/// <summary>
/// Get the current arg value as int
/// </summary>
/// <returns>int value</returns>
int CLIArg::getValueInt()
{
	/*
	Some conversions can fail for whatever reason,
	so try stoi as well.
	*/
	try
	{
		return std::get<int>(this->getValue());
	}
	catch (const std::bad_variant_access)
	{
		return stoi(this->getValueString());
	}
}

/// <summary>
/// get the current arg value as a string.
/// </summary>
/// <returns>std::string value</returns>
std::string CLIArg::getValueString()
{
	return std::get<std::string>(this->value);
}

/// <summary>
/// Create a new CLI handler from a vector of arguments to handle
/// </summary>
/// <param name="desiredArgs">CLIArgs to handle</param>
CLIHandler::CLIHandler(std::vector<CLIArg> desiredArgs)
{
	this->definedArgs = desiredArgs;
	for (CLIArg arg : definedArgs)
	{
		if (arg.isArgRequired())
		{
			CLIHandler::argTracker.push_back({ arg.getLongFlag(),false });
		}
	}
}

/// <summary>
/// Get the matching arg from a given string.
/// Returns the arg 'spec' rather than its handled equivalent.
/// </summary>
/// <param name="longFlag">string to use in search</param>
/// <param name="argBuffer">pointer to CLIArg to update</param>
/// <returns></returns>
bool CLIHandler::getDefinedArg(std::string longFlag, CLIArg* argBuffer)
{

	if (!longFlag.empty() && longFlag[0] == '-')
	{
		try
		{
			// checking for '-' does not work with negative numbers
			// so check if the val can be converted to an int.
			int isnum = stoi(longFlag);
			return false;
		}
		catch (const std::exception&)
		{
			longFlag.erase(0, 1);
			if (longFlag.size() > 1 && longFlag[0] == '-')
			{
				longFlag.erase(0, 1);
			}
			for (CLIArg possibleArg : this->definedArgs)
			{
				if (longFlag.size() == 1 && longFlag.c_str()[0] == possibleArg.getShortFlag() ||
					longFlag.size() > 1 && longFlag == possibleArg.getLongFlag())
				{
					*argBuffer = possibleArg;
					return true;
				}
			}
			throw ArgException(std::format("Argument: {} not supported", longFlag));
		}
	}
	else
	{
		return false;
	}
}

/// <summary>
/// Get the current versions of a given arg after parsing.
/// Returns multiple args as most can be defined mulitple times.
/// If an arg is not found but a default is defined will return that instead.
/// </summary>
/// <param name="longFlag">Arg to search</param>
/// <returns>Vector of matching arguments</returns>
std::vector<CLIArg> CLIHandler::getHandledArg(std::string longFlag)
{
	std::vector<CLIArg> selectedArgs{};
	for (CLIArg argument : this->handledArgs ) {
		if (argument.getLongFlag() == longFlag)
		{
			selectedArgs.push_back(argument);
		}
	}
	// if the arg is missing but is defined with a default then return that
	if (selectedArgs.size() == 0)
	{
		for (CLIArg definedArg : this->definedArgs)
		{
			if (definedArg.getLongFlag() == longFlag && definedArg.isArgDefaultable())
			{
				selectedArgs.push_back(definedArg);
				return selectedArgs;
			}
		}
		// if we get here then no arg was found and we don't have a default 
		// this can occur when a non value flag is required
		return selectedArgs;
	}
	return selectedArgs;
}

/// <summary>
/// parse the "raw" args from the CLI into a more usable format
/// </summary>
bool CLIHandler::parseArgs(int argc, char* argv[])
{
	std::vector<std::string> rawArgs(argv + 1, argv + argc);
	CLIArg argBuffer;
	bool isHelpPresent = false;

	for (std::string argString : rawArgs)
	{
		/*
		argBuffer is only updated when a new flag is sent so, 
		this system can support multi value args with no work around.
		*/
		bool argExpected = getDefinedArg(argString, &argBuffer);

		if (!argExpected && argBuffer.isValueExpected())
		{
			argBuffer.setValue(argString); // will run validator.
			this->handledArgs.push_back(argBuffer);
		}
		else if (argExpected && !argBuffer.isValueExpected())
		{
			argBuffer.setValue(true); // will also run validator but will always return true/
			this->handledArgs.push_back(argBuffer);
		}
		if (argBuffer.isArgRequired())
		{
			for (size_t i = 0; i < this->argTracker.size(); i++)
			{
				if (argBuffer.getLongFlag() == this->argTracker[i].name) {
					this->argTracker[i].isPresent = true;
				}
			}
		}
	}
	if (this->getHandledArg("help").size() > 0)
	{
		return false;
	}
	// make sure that all required args are present
	// but only if a help flag is not present
	for (size_t i = 0; i < this->argTracker.size(); i++)
	{
		if (!this->argTracker[i].isPresent)
		{
			throw ArgException(std::format("Missing argument: ({}) is required!", this->argTracker[i].name));
		}
	}
	return true;
}

