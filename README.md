# Blackfin Bootstream Parser

This is a reverse engineering tool for parsing bootstream captures from Blackfin devices.

The python module accepts data in CSV form, and can produce loader files `.ldr` of the bootstream and binary `.bin` of the formatted memory ranges as the target would load them (in theory).

```
$ ./bootparse.py samples/bootstream_spi.csv
Blackfin Bootstream Parser
=========================================
Parsing CSV file:  ../eh-mbx/samples/bootstream_spi.csv
Output file:  boot.ldr
SRAM file:  None
Instruction ROM file:  None
=========================================
Loaded 37089 SPI transactions
Using 24-bit addressing
Parsed 18 SPI read blocks
Wrote 37012 bytes to boot.ldr
Found 11 block headers in bootstream
```

This currently only supports for the ADSP-BF59x family of devices running in SPI Master mode. Support for ADSP-BF53x devices (in a similar mode) is planned. Testing is planned with a BF592 and BF531, respectively. Support could be added for other booting modes (UART, PPI, and SPI Slave) and other Blackfin families (BF7xx, BF6xx, and the rest of BF5xx).

## Usage

```
$ ./bootparse.py -h
usage: bootparse.py [-h] [-o OUTPUT] [-s SRAM] [-i INSTRUCTION_ROM] [--print-reads] [--print-headers] csv_file

SPI trace parser for Analog Devices Blackfin devices.
Parses a CSV file containing SPI trace data and outputs a loader file.
                                        

positional arguments:
  csv_file              CSV file containing SPI trace data

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Output file name for the loader file
  -s, --sram SRAM       Output file name for the SRAM
  -i, --instruction_rom INSTRUCTION_ROM
                        Output file name for the instruction ROM
  --print-reads         Print a table of SPI read addresses and lengths
  --print-headers       Print a table of bootstream block headers

Examples:
    bootparse.py spi_trace.csv
    bootparse.py spi_trace.csv -o boot.ldr
    bootparse.py spi_trace.csv -s sram.bin -i bootrom.bin
    bootparse.py spi_trace.csv --print-reads
    bootparse.py spi_trace.csv --print-headers
    bootparse.py spi_trace.csv -o boot.ldr -s sram.bin -i bootrom.bin --print-reads --print-headers
```