#pragma once
#include<tuple>
#include<string>
#include "CLIHandler.h"

// simple way to return an error message as well as a result.
struct validationResult
{
	bool outcome;
	std::string outcomeMessage;
};

validationResult validatePort(CLIArg::ArgValue portValue);

validationResult validateTarget(CLIArg::ArgValue hostValue);

validationResult validateThreads(CLIArg::ArgValue threadsValue);

validationResult validateDelay(CLIArg::ArgValue delayValue);
