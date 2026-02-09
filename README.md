# Manual PE Loader

This project is a modern PE Loader designed for x64 PE (exe or dll) only. It is currently written in C++ with classic Windows API. 
Later, this project will be converted in C to use native function only.

## Supports

* Map each sections to their VA.
* Apply relocations
* Fix imports (by ordinal, name or forwarder)
* Fix delay-load imports (by ordinal, name or forwarder)
* Apply load config directory
* Register exception handlers
* Call TLS callbacks



