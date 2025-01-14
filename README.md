# NetMap - C++ Port Scanner

NetMap is a simple port scanner written in C++. It is multithreaded and currently only supports TCP and ICMP scans. Versioning techniques are not yet implemented, so all results indicate what should be present rather than what is present.

This is more of a project for working on my C++ skills / general programming skills than anything else. For that reason this software only uses Win32 and the C++ (20) standard library. This is loosely inspired by the [software from scratch series](https://youtube.com/playlist?list=PLRxiTqSapP_ySVJqRYy0veJZBNkwtx6ZQ&feature=shared), though modern C++ is much less restrictive than C.

These restrictions complicate the codebase quite a bit, as many features like CLI parsing have to be implemented in the software itself, rather than being imported from elsewhere. This is more beneficial as a learning exercise and does have the small benefit of removing any external requirements beyond Windows. 

## Usage
This is a Win32 application and will not work outside of Windows. However, it is packaged as a standalone .exe for simplicity. The following arguments are supported, all args can take multiple values:

1. -t (--target) (REQUIRED) target to scan. Note that this can be a IP address, a CIDR notated address or a hostname.
2. -p (--port) ports to scan. By default the system scans any registered ports below 3500, this is likely to change at some point.
3. -f (--fast-mode) fast mode. This skips the ICMP scan and assumes that all targets are active.
4. -n (--net-threads) number of threads to use during scanning.
5. -d (--delay) wait for a certain time between each host during scanning. Specified in as milliseconds.
6. -v (--verbose) toggles verbose output.

## Credit & License

Inspiration is taken from *nmap*, with *nmap's* known-services file being used to support this software. To support this, *NetMap* is licensed under GPL-V2. 
