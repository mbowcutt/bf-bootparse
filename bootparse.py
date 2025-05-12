#!/usr/bin/env python3

"""Blackfin Bootstream Parser"""

import argparse
import csv
import sys

SPI_CMD_READ        = 0x03
SPI_CMD_READ_FAST   = 0x0B

STATE_PROCESS_HEADER = 0
STATE_COPY_DATA = 1

class BootstreamParser():
    """
    Loads a CSV file containing SPI trace of the bootstream.

    Provides functions for parsing the SPI stream for read commands, formatting
    the data returned as bootstream headers and data, and processing them into
    binaries for the SRAM and Boot ROM.
    """

    def __init__(self, csv_filename):
        self.cursor = 0
        self.addr_bytesize = None
        self.stream = self.parse_file_csv(csv_filename)

    def parse_file_csv(self, filename):
        """
        Parses a CSV containing SPI trace data.

        This function reads a CSV file where each row represents a single SPI
        transaction. It extracts the MOSI (Master Out Slave In) and MISO
        (Master In Slave Out) valuesfrom the CSV and stores them as
        dictionaries in a list.

        Args:
            filename (str): The path to the CSV file to be parsed.

        Returns:
            list[dict]: A list of dictionaries, where each dictionary contains:
                "MOSI" (int)
                "MISO" (int)
        """
        with open(filename, 'r', encoding='utf-8') as bstream_file:
            next(bstream_file) # TODO parse header columns

            spi_byte_arr = []
            for line in csv.reader(bstream_file):
                spi_byte_arr.append({"MOSI": int(line[2],16),
                                     "MISO": int(line[3],16)})
        return spi_byte_arr


    def detect_address_size(self):
        """
        Detects the address size of the SPI slave device.

        This function determines the addressing scheme (8-bit, 16-bit, 24-bit,
        or 32-bit) used by the SPI slave device. It analyzes the SPI stream by
        checking the MISO (Master In Slave Out) response to specific SPI read
        commands (SPI_CMD_READ or SPI_CMD_READ_FAST). The address size is
        determined based on the number of consecutive 0xFF bytes in the MISO 
        response before the data begins.

        Args:
            None
        Returns:
            None
        """

        byte = self.stream[self.cursor]['MOSI']
        self.cursor += 1

        if SPI_CMD_READ_FAST == byte:
            self.cursor += 1 # read dummy byte
        elif SPI_CMD_READ != byte:
            raise RuntimeError("Invalid SPI Read Command")

        bytesize = 1
        while (0xFF == self.stream[self.cursor + bytesize]['MISO']) \
                and (bytesize <= 4):
            bytesize += 1

        if bytesize > 4:
            raise RuntimeError("Invalid address size")

        self.addr_bytesize = bytesize
        self.cursor += bytesize+1


    def parse_memory_blocks(self):
        """
        Reads memory blocks from the SPI stream and stores them as SpiReadBlock objects.

        This function processes the SPI stream to identify and extract memory blocks 
        associated with SPI read commands (SPI_CMD_READ). For each read command, it 
        parses the target address and collects the data bytes until the end of the 
        block. The extracted blocks are stored in the `self.blocks` list.

        Args:
            None
        Returns:
            list[SpiReadBlock]: A list of SpiReadBlock objects representing the
                                parsed memory blocks.
        """

        blocks = []
        while (self.cursor < len(self.stream)) and \
                (SPI_CMD_READ == self.stream[self.cursor]['MOSI']):
            self.cursor += 1

            addr = self.__parse_address()
            data = []
            while (self.cursor < len(self.stream)) and \
                    (0x00 == self.stream[self.cursor]['MOSI']):
                data.append(self.stream[self.cursor]['MISO'])
                self.cursor += 1

            blocks.append(SpiReadBlock(addr, data))

        return blocks


    def __parse_address(self):
        """
        Parses an address from the SPI stream.

        This function extracts an address from the SPI stream based on the current 
        `self.addr_bytesize`. It reads the specified number of bytes (determined by 
        `self.addr_bytesize`) from the MOSI (Master Out Slave In) field of the SPI stream 
        and combines them into a single integer representing the address.

        Returns:
            int: The parsed address as an integer.
        """
        addr = 0
        for byte in self.stream[self.cursor : self.cursor + self.addr_bytesize]:
            addr = (addr << 8) | byte['MOSI']

        self.cursor += self.addr_bytesize
        return addr


    def build_ldr_file(self, blocks, ldr_filename="boot.ldr"):
        """
        Builds a loader file from the parsed blocks.

        This function creates a loader file by writing the parsed blocks to the
        specified `ldr_filename`. The blocks are written in a specific format
        that can be used for further processing or analysis.

        Args:
            ldr_filename (str): The name of the loader file to be created.
            blocks (list[SpiReadBlock]): The list of parsed blocks to be written.
        Returns:
            int: The number of bytes written to the loader file.
        """

        bytes_written = 0
        with open(ldr_filename, "wb") as ldr_file:
            for block in blocks:
                for byte in block.data:
                    ldr_file.write(byte.to_bytes())
                    bytes_written += 1
        return bytes_written

    def handle_blocks(self, blocks,
                      sram_filename="sram.bin", bootrom_filename="bootrom.bin"):
        """
        Processes the incoming data block as a block header or as raw data.

        This function reads the incoming data block and either constructs a
        block header, or copies the data to the target address specified in
        a previous block header. The block header is validated, and depending
        on flags, it may be ignored or indicate a fill operation. Otherwise,
        the state is changed from `STATE_PROCESS_HEADER` to `STATE_COPY_DATA`
        so the next block can be processed as data.

        Args:
            block (SpiReadBlock): The incoming data block to be processed.
        Returns:
            None
        """

        state = STATE_PROCESS_HEADER
        headers = []

        for block in blocks:
            if STATE_PROCESS_HEADER == state:
                header = block.parse_header()
                if header is not None:
                    headers.append(header)
                    if header.validate():
                        if header.ignore():
                            continue

                        if header.is_fill():
                            header.apply_fill(sram_filename, bootrom_filename)
                        else:
                            state = STATE_COPY_DATA
                    else:
                        print("Header is invalid")
                        raise RuntimeError

            elif STATE_COPY_DATA == state:
                headers[-1].copy_data(block, sram_filename, bootrom_filename)
                state = STATE_PROCESS_HEADER

        return headers


class SpiReadBlock():
    """
    Represents an address and data block from a SPI Read command.

    This class is used to store the address and data received from a SPI
    Read command. It also provides methods to parse a BF59xBlkHdr from
    the data block.
    """

    header_buf = []
    count = 0


    def __init__(self, addr, data):
        self.addr = addr
        self.data = data
        self.block_index = SpiReadBlock.count
        SpiReadBlock.count += 1


    def __str__(self):
        return f"{self.block_index}\t" + \
               f"0x{self.addr:06X}\t" + \
               f"0x{self.addr+len(self.data):06X}\t" + \
               f"{len(self.data):>6}"


    def __len__(self):
        return len(self.data)


    @staticmethod
    def print_table_header():
        """
        Prints the header of the block table.

        This function prints the header of the block table, which includes
        the column names for the start address, end address, and size.
        """

        print("#\tStart Addr\tEnd Addr\t  Size")
        print("----------------------------------------------")


    @staticmethod
    def print_block_table(blocks):
        """
        Prints the block table.

        This function prints the block table, which includes the start address,
        end address, and size of each block.

        Args:
            blocks (list[SpiReadBlock]): The list of blocks to be printed.
        Returns:
            None
        """

        SpiReadBlock.print_table_header()
        for block in blocks:
            print(f"{block}")


    def parse_header(self):
        """
        Parses the header from the incoming data.

        This function checks the length of `self.data` to determine if it
        contains a partial or complete header. Once a complete header is 
        obtained a `BF59xBlkHdr` object is created and returned.

        Args:
            None
        Returns:
            BF59xBlkHdr: The parsed block header object.
        """

        if 16 == len(self.data):
            return BF59xBlkHdr(self.data, self.block_index)

        if 8 == len(self.data):
            for byte in self.data:
                SpiReadBlock.header_buf.append(byte)
            if 16 == len(self.header_buf):
                header = BF59xBlkHdr(SpiReadBlock.header_buf,
                                           self.block_index)
                SpiReadBlock.header_buf.clear()
                return header
            if 16 < len(SpiReadBlock.header_buf):
                raise RuntimeError
        else:
            raise RuntimeError


class BF59xBlkHdr():
    """
    Represents a ADSP BF59x bootstream block header.

    This class represents a stream block header on BF59x devices. It contains
    a block code, target address, byte count, and an argument. The class has
    functions for header validatoin, memory range checks, and data filling and
    copying.
    """

    HDRSGN          = 0xAD000000
    HDRSGN_MASK     = 0XFF000000
    HDRCHK_MASK     = 0x00FF0000

    BFLAG_FINAL     = 0x00008000
    BFLAG_FIRST     = 0x00004000
    BFLAG_INDIRECT  = 0x00002000
    BFLAG_IGNORE    = 0x00001000
    BFLAG_INIT      = 0x00000800
    BFLAG_CALLBACK  = 0x00000400
    BFLAG_QUICKBOOT = 0x00000200
    BFLAG_FILL      = 0x00000100
    BFLAG_AUX       = 0x00000020
    BFLAG_SAVE      = 0x00000010
    BFLAG_MASK      = 0x0000FF30

    DMA_MASK        = 0x0000000F

    header_count = 0


    def __init__(self, raw, block_idx):
        self.fields = { "BLOCK CODE": int.from_bytes(reversed(raw[0:4])),
                        "TARGET ADDRESS": int.from_bytes(reversed(raw[4:8])),
                        "BYTE COUNT": int.from_bytes(reversed(raw[8:12])),
                        "ARGUMENT": int.from_bytes(reversed(raw[12:16])) }
        self.block_idx = block_idx
        self.header_idx = BF59xBlkHdr.header_count
        BF59xBlkHdr.header_count += 1


    def __str__(self):
        return f"{self.header_idx}\t" +\
               f"{self.fields["BLOCK CODE"]:08X}\t" + \
               f"{self.fields["TARGET ADDRESS"]:08X}\t" + \
               f"{self.fields["BYTE COUNT"]:08X}\t" + \
               f"{self.fields["ARGUMENT"]:08X}"


    @staticmethod
    def print_table_header():
        """
        Prints the header of the block header table.

        This function prints the header of the block header table, which
        includes the column names for the block code, target address,
        byte count, and argument.
        """

        print("#\tBlock Code\tTarget Addr\tByte Count\tArgument")
        print("----------------------------------------------------------------")


    @staticmethod
    def print_header_table(headers):
        """
        Prints the block header table.

        This function prints the block header table, which includes the
        block code, target address, byte count, and argument of each
        block header.

        Args:
            headers (list[BF59xBlkHdr]): The list of block headers to be printed.
        Returns:
            None
        """

        BF59xBlkHdr.print_table_header()
        for header in headers:
            print(f"{header}")


    def validate(self):
        """
        Validates the block header.

        This function checks the block header for validity by verifying the
        header signature.

        TODO: Check CRC.

        Args:
            None
        Returns:
            bool: True if the block header is valid, False otherwise.
        """

        # TODO Check CRC

        return BF59xBlkHdr.HDRSGN == \
                   (self.fields["BLOCK CODE"] & BF59xBlkHdr.HDRSGN_MASK)


    def flags(self):
        """
        Returns the flags of the block header.
        This function extracts the flags from the block header. The flags
        are used to determine the type of operation to be performed on
        the target address.
        Args:
            None
        Returns:
            int: The flags of the block header.
        """

        return self.fields["BLOCK CODE"] & BF59xBlkHdr.BFLAG_MASK


    def ignore(self):
        """
        Checks if the block header should be ignored.

        This function checks if the block header has the ignore flag set.
        If the ignore flag is set, the block header will be ignored.

        Args:
            None
        Returns:
            bool: True if the block header should be ignored, False otherwise.
        """

        return (self.flags() & BF59xBlkHdr.BFLAG_IGNORE) != 0


    def is_fill(self):
        """
        Checks if the block header is a fill operation.

        This function checks if the block header has the fill flag set.
        If the fill flag is set, the block header will be treated as a
        fill operation.

        Args:
            None
        Returns:
            bool: True if the block header is a fill operation, False otherwise.
        """

        return (self.flags() & BF59xBlkHdr.BFLAG_FILL) != 0


    def check_bounds(self, start_addr, end_addr):
        """
        Checks if the target address is within the specified bounds.

        This function checks if the target address is within the specified
        start and end addresses. If the target address is outside of the
        bounds, a RuntimeError is raised.

        Args:
            start_addr (int): The start address of the range.
            end_addr (int): The end address of the range.
        Returns:
            None
        """

        block_start = self.fields["TARGET ADDRESS"]
        block_end = self.fields["TARGET ADDRESS"] + self.fields["BYTE COUNT"]
        return ((block_start >= start_addr) and (block_end <= end_addr))


    def is_within_sram(self):
        """
        Checks if the target address is within the SRAM range.

        This function checks if the target address fits within the SRAM range
        of the BF59x memory map (0xFF800000 to 0xFF807FFF).
        """

        return self.check_bounds(0xFF800000, 0xFF807FFF)


    def is_within_bootrom(self):
        """
        Checks if the target address is within the Boot ROM range.

        This function checks if the target address fits within the Boot ROM
        range of the BF59x memory map (0xFFA00000 to 0xFFA07FFF).
        """

        return self.check_bounds(0xFFA00000, 0xFFA07FFF)


    def apply_fill(self, sram_filename, bootrom_filename):
        """
        Fills the target address with the specified argument.

        This function fills `self.fields["TARGET ADDRESS"]` with `self.fields["ARGUMENT"]` for a
        count of `self.fields["BYTE COUNT"]` bytes, which must be divisible by 4.

        Args:
            sram_file (file): The file object for the SRAM.
            bootrom_file (file): The file object for the Boot ROM.
        Returns:
            None
        """

        if self.fields["BYTE COUNT"] % 4 != 0:
            raise RuntimeError("Byte count must be divisible by 4")

        if self.is_within_sram():
            if sram_filename is None:
                return

            with open(sram_filename, "wb") as sram_file:
                sram_file.seek(self.fields["TARGET ADDRESS"] - 0xFF800000, 0)
                for _ in range(0, self.fields["BYTE COUNT"] // 4):
                    sram_file.write(int(self.fields["ARGUMENT"]).to_bytes(4))

        elif self.is_within_bootrom():
            if bootrom_filename is None:
                return

            with open(bootrom_filename, "wb") as bootrom_file:
                bootrom_file.seek(self.fields["TARGET ADDRESS"] - 0xFFA00000, 0)
                for _ in range(0, self.fields["BYTE COUNT"] // 4):
                    bootrom_file.write(int(self.fields["ARGUMENT"]).to_bytes(4))

        else:
            raise RuntimeError


    def copy_data(self, block, sram_filename, bootrom_filename):
        """
        Copies the data from the block to the target address.
        
        This function copies `self.fields["BYTE COUNT"]` bytes from the incoming
        `block` to the target address specified in `self.fields["TARGET ADDRESS"]`.

        Args:
            block (SpiReadBlock): The incoming data block to be copied.
            sram_file (file): The file object for the SRAM.
            bootrom_file (file): The file object for the Boot ROM.

        Returns:
            None
        """

        if self.is_within_sram():
            if sram_filename is None:
                return

            with open(sram_filename, "wb") as sram_file:
                sram_file.seek(self.fields["TARGET ADDRESS"] - 0xFF800000, 0)
                for byte in block.data[0:self.fields["BYTE COUNT"]]:
                    sram_file.write(byte.to_bytes())

        elif self.is_within_bootrom():
            if bootrom_filename is None:
                return

            with open(bootrom_filename, "wb") as bootrom_file:
                bootrom_file.seek(self.fields["TARGET ADDRESS"] - 0xFFA00000, 0)
                for byte in block.data[0:self.fields["BYTE COUNT"]]:
                    bootrom_file.write(byte.to_bytes())

        else:
            raise RuntimeError


if __name__ == "__main__":

    argparser = argparse.ArgumentParser(prog='bootparse.py',
                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                        description='''
SPI trace parser for Analog Devices Blackfin devices.
Parses a CSV file containing SPI trace data and outputs a loader file.
                                        ''',
                                        epilog='''
Examples:
    bootparse.py spi_trace.csv
    bootparse.py spi_trace.csv -o boot.ldr
    bootparse.py spi_trace.csv -s sram.bin -i bootrom.bin
    bootparse.py spi_trace.csv --print-reads
    bootparse.py spi_trace.csv --print-headers
    bootparse.py spi_trace.csv -o boot.ldr -s sram.bin -i bootrom.bin --print-reads --print-headers
                                        ''')
    argparser.add_argument('csv_file', type=str,
                            help='CSV file containing SPI trace data')
    argparser.add_argument('-o', '--output', type=str,
                            help='Output file name for the loader file',
                            default='boot.ldr')
    argparser.add_argument('-s', '--sram', type=str,
                            help='Output file name for the SRAM',
                            default=None)
    argparser.add_argument('-i', '--instruction_rom', type=str,
                            help='Output file name for the instruction ROM',
                            default=None)
    argparser.add_argument('--print-reads', action='store_true',
                            help='Print a table of SPI read addresses and lengths')
    argparser.add_argument('--print-headers', action='store_true',
                            help='Print a table of bootstream block headers')
    args = argparser.parse_args()

    print("Blackfin Bootstream Parser")
    print("=========================================")
    print("Parsing CSV file: ", args.csv_file)
    print("Output file: ", args.output)
    print("SRAM file: ", args.sram)
    print("Instruction ROM file: ", args.instruction_rom)
    print("=========================================")

    # Check if the CSV file exists
    if not args.csv_file:
        print("Error: CSV file not specified.")
        sys.exit(1)

    # Parse the CSV file
    parser = BootstreamParser(args.csv_file)
    print(f"Loaded {len(parser.stream)} SPI transactions")

    # Detect the address size
    parser.detect_address_size()
    print(f"Using {parser.addr_bytesize * 8}-bit addressing")

    # Parse the SPI reads
    spi_read_blocks = parser.parse_memory_blocks()
    print(f"Parsed {len(spi_read_blocks)} SPI read blocks")

    # Build the loader file
    bytes_written = parser.build_ldr_file(spi_read_blocks, args.output)
    print(f"Wrote {bytes_written} bytes to {args.output}")

    # Handle the blocks and create SRAM and Boot ROM files
    bootstream_blk_headers = parser.handle_blocks(spi_read_blocks,
                                                  args.sram,
                                                  args.instruction_rom)
    print(f"Found {len(bootstream_blk_headers)} block headers in bootstream")

    # Optionally print the SPI read blocks and bootstream headers
    if args.print_reads:
        print("SPI Read Blocks:")
        SpiReadBlock.print_block_table(spi_read_blocks)
        print()
    if args.print_headers:
        print("Bootstream Headers:")
        BF59xBlkHdr.print_header_table(bootstream_blk_headers)
        print()
