"""Blackfin Bootstream Parser"""

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
        self.state = STATE_PROCESS_HEADER
        self.header_buf = []
        self.headers = []
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
            None
        """

        with open(ldr_filename, "wb") as ldr_file:
            for block in blocks:
                for byte in block.data:
                    ldr_file.write(byte.to_bytes())

    def handle_block(self, block,
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

        if STATE_PROCESS_HEADER == self.state:

            header = block.parse_header()
            if header is not None:
                self.headers.append(header)
                if header.validate():
                    if header.block_code & BFLAG_IGNORE:
                        return
                    if header.block_code & BFLAG_FILL:
                        header.apply_fill(sram_filename, bootrom_filename)
                    else:
                        self.state = STATE_COPY_DATA
                else:
                    print("Header is invalid")
                    raise RuntimeError

        elif STATE_COPY_DATA == self.state:
            self.headers[-1].copy_data(block, sram_filename, bootrom_filename)
            self.state = STATE_PROCESS_HEADER

class SpiReadBlock():
    """
    Represents an address and data block from a SPI Read command.

    This class is used to store the address and data received from a SPI
    Read command. It also provides methods to parse a StreamBlockHeader from
    the data block.
    """

    header_buf = []

    def __init__(self, addr, data):
        self.addr = addr
        self.data = data

    def __str__(self):
        return f"0x{self.addr:06X}\t0x{self.addr+len(self.data):06X}\t{len(self.data):>6}"

    def __len__(self):
        return len(self.data)

    def parse_header(self):
        """
        Parses the header from the incoming data.

        This function checks the length of `self.data` to determine if it
        contains a partial or complete header. Once a complete header is 
        obtained a `StreamBlockHeader` object is created and returned.

        Args:
            None
        Returns:
            StreamBlockHeader: The parsed block header object.
        """

        if 16 == len(self.data):
            return StreamBlockHeader(self.data)

        if 8 == len(self.data):
            for byte in self.data:
                SpiReadBlock.header_buf.append(byte)
            if 16 == len(self.header_buf):
                header = StreamBlockHeader(SpiReadBlock.header_buf)
                SpiReadBlock.header_buf.clear()
                return header
            if 16 < len(SpiReadBlock.header_buf):
                raise RuntimeError
        else:
            raise RuntimeError


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

class StreamBlockHeader():
    """
    Represents a stream block header.

    This class represents a stream block header on BF59x devices. It contains
    a block code, target address, byte count, and an argument. The class has
    functions for header validatoin, memory range checks, and data filling and
    copying.
    """

    def __init__(self, raw):
        self.block_code = int.from_bytes(reversed(raw[0:4]))
        self.target_address = int.from_bytes(reversed(raw[4:8]))
        self.byte_count = int.from_bytes(reversed(raw[8:12]))
        self.argument = int.from_bytes(reversed(raw[12:16]))

    def __str__(self):
        return f"{block_header.block_code:08X}\t" + \
               f"{block_header.target_address:08X}\t" + \
               f"{block_header.byte_count:08X}\t" + \
               f"{block_header.argument:08X}"

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

        return HDRSGN == (self.block_code & HDRSGN_MASK)

    def is_within_sram(self):
        """
        Checks if the target address is within the SRAM range.

        This function checks if the target address fits within the SRAM range
        of the BF59x memory map (0xFF800000 to 0xFF807FFF).
        """

        return (self.target_address >= 0xFF800000) and \
                ((self.target_address + self.byte_count) <= 0xFF807FFF)

    def is_within_bootrom(self):
        """
        Checks if the target address is within the Boot ROM range.

        This function checks if the target address fits within the Boot ROM
        range of the BF59x memory map (0xFFA00000 to 0xFFA07FFF).
        """

        return (self.target_address >= 0xFFA00000) and \
                ((self.target_address + self.byte_count) <= 0xFFA07FFF)

    def apply_fill(self, sram_filename, bootrom_filename):
        """
        Fills the target address with the specified argument.

        This function fills `self.target_address` with `self.argument` for a
        count of `self.byte_count` bytes, which must be divisible by 4.

        Args:
            sram_file (file): The file object for the SRAM.
            bootrom_file (file): The file object for the Boot ROM.
        Returns:
            None
        """

        if self.byte_count % 4 != 0:
            raise RuntimeError("Byte count must be divisible by 4")

        if self.is_within_sram():
            with open(sram_filename, "wb") as sram_file:
                sram_file.seek(self.target_address - 0xFF800000, 0)
                for _ in range(0, self.byte_count // 4):
                    sram_file.write(int(self.argument).to_bytes(4))

        elif self.is_within_bootrom():
            with open(bootrom_filename, "wb") as bootrom_file:
                bootrom_file.seek(self.target_address - 0xFFA00000, 0)
                for _ in range(0, self.byte_count // 4):
                    bootrom_file.write(int(self.argument).to_bytes(4))

        else:
            raise RuntimeError

    def copy_data(self, block, sram_filename, bootrom_filename):
        """
        Copies the data from the block to the target address.
        
        This function copies `self.byte_count` bytes from the incoming
        `block` to the target address specified in `self.target_address`.

        Args:
            block (SpiReadBlock): The incoming data block to be copied.
            sram_file (file): The file object for the SRAM.
            bootrom_file (file): The file object for the Boot ROM.

        Returns:
            None
        """

        if self.is_within_sram():
            with open(sram_filename, "wb") as sram_file:
                sram_file.seek(self.target_address - 0xFF800000, 0)
                for byte in block.data[0:self.byte_count]:
                    sram_file.write(byte.to_bytes())

        elif self.is_within_bootrom():
            with open(bootrom_filename, "wb") as bootrom_file:
                bootrom_file.seek(self.target_address - 0xFFA00000, 0)
                for byte in block.data[0:self.byte_count]:
                    bootrom_file.write(byte.to_bytes())

        else:
            raise RuntimeError

parser = BootstreamParser(sys.argv[1])
parser.detect_address_size()
spi_read_blocks = parser.parse_memory_blocks()
parser.build_ldr_file(spi_read_blocks)

print("SPI Read Blocks:")
print("#\tStart Addr\tEnd Addr\t  Size")
print("----------------------------------------------")
for index, stream_block in enumerate(spi_read_blocks):
    print(f"{index}\t{stream_block}")
    parser.handle_block(stream_block)

print()
print("Bootstream Headers:")
print("#\tBlock Code\tTarget Addr\tByte Count\tArgument")
print("----------------------------------------------------------------")
for index, block_header in enumerate(parser.headers):
    print(f"{index}\t{block_header}")
