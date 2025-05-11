# Blackfin Bootstream Parser

This is a reverse engineering tool for parsing bootstream captures from Blackfin devices.

The python module accepts data in CSV form, and can produce loader files `.ldr` of the bootstream and binary `.bin` of the formatted memory ranges as the target would load them (in theory). 

This currently only supports for the ADSP-BF59x family of devices running in SPI Master mode. Support for ADSP-BF53x devices (in a similar mode) is planned. Testing is planned with a BF592 and BF531, respectively. Support could be added for other booting modes (UART, PPI, and SPI Slave) and other Blackfin families (BF7xx, BF6xx, and the rest of BF5xx).