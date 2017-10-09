# FridaKernelAgent.kext

Experimental kernel driver for system-wide early instrumentation on macOS.

Also improves Frida's stealthiness and allows it to get into any process.

## Installation

1. Open FridaKernelAgent.xcodeproj and build it with Xcode.
2. Review `reload.sh`, adjusting it to match your system.
3. Run `reload.sh` to install and load the driver.
