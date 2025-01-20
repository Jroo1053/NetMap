#pragma once
#include <cstddef>
#include <Windows.h>
#include <string>
class Resource
{
public:
	struct Parameters
	{
		std::size_t resourceSize = 0;
		void* ptr = nullptr;
	};

private:
	HRSRC hResource = nullptr;
	HGLOBAL hMemory = nullptr;
	Parameters p;

public:
	Resource(int resource_id, const std::string& resource_class) {
		hResource = FindResourceA(nullptr, MAKEINTRESOURCEA(resource_id), resource_class.c_str());
		hMemory = LoadResource(nullptr, hResource);

		p.resourceSize = SizeofResource(nullptr, hResource);
		p.ptr = LockResource(hMemory);
	}
	auto& GetResource() const {
		return p;
	}

	auto GetResourceString() const {
		std::string_view dst;
		if (p.ptr != nullptr)
			dst = std::string_view(reinterpret_cast<char*>(p.ptr), p.resourceSize);
		return dst;
	}
};

