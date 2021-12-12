# Kernel Usermode Communication Method
Manually mapped kernel driver using system thread to process shared memory as a communication method with Usermode client.

The driver is manually mapped with a custom version of TheCruz kdmapper, altered to allow for custom driver entry point to receive necessary information to communicate with usermode client. It uses a system thread to continuosly await for requests by parsing the shared memory for predefined operations.
The driver is also cleaning garbage left overs from using intel's vulnarable driver to manually map our driver.

The driver as of now has functionallity to:
* read/write arbitrary virtual memory from and to any process
* get base address of a specific process 
* ping method to test out communication effectiveness.

# TODO
* Hide system thread from system enumeration
* Resolve and bypass NMI callbacks
* Implement read/write physical memory to not use KeStackAttachProcess
* Get module information method to retreive base address and size of loaded modules of a process