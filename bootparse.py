import sys
import os
import time
import csv

print('Michael\'s ADSP-BF59x Boot Stream Parser')

class SpiByte:
    def __init__(self, mosi, miso):
        self.mosi = mosi
        self.miso = miso

class SpiReadBlock():
    def __init__(self, addr, data):
        self.addr = addr
        self.data = data

    def __str__(self):
        return "\t0x{:06X}\t0x{:06X}\t({})".format(self.addr, self.addr + len(self.data), len(self.data))

    def __len__(self):
        return len(self.data)

SPI_CMD_READ        = 0x03
SPI_CMD_READ_FAST   = 0x0B

MEM_ADDR_BITSIZE_UNINIT = 0
MEM_ADDR_BITSIZE_8 = 1
MEM_ADDR_BITSIZE_16 = 2
MEM_ADDR_BITSIZE_24 = 3
MEM_ADDR_BITSIZE_32 = 4

STATE_PROCESS_HEADER = 0
STATE_COPY_DATA = 1
STATE_FILL = 2

class BootstreamParser():

    def __init__(self, filename):
        self.cursor = 0
        self.addr_bitsize = MEM_ADDR_BITSIZE_UNINIT
        self.state = STATE_PROCESS_HEADER
        self.header_buf = []
        self.header = None
        self.stream = self.parse_file_csv(filename)
        self.loader_file = open("bootstream.ldr", "wb")
        self.data_file = open("SRAM.bin", "wb")
        self.instruction_file = open("boot.bin", "wb")

    def parse_file_csv(self, filename):
        with open(filename, 'r') as bstream_file:
            csv_header = next(bstream_file)

            spi_byte_arr = []
            for line in csv.reader(bstream_file):
                spi_byte_arr.append(SpiByte(int(line[2],16), int(line[3],16)))

        return spi_byte_arr

    # Detects if the SPI memory device requires an 8, 16, 24, or 32 bit addressing scheme
    def detect_address_size(self):
        print("SPI Read Command - Detecting Address Size")

        if (0x0B == self.stream[self.cursor].mosi):
            fastread = True
        elif (0x03 == self.stream[self.cursor].mosi):
            fastread = False
        else:
            raise RuntimeError
        
        self.cursor += 1

        data_idx = 1
        end_idx = 5 if fastread else 4
        stream = self.stream[self.cursor : self.cursor + end_idx]
        
        while (0xFF == stream[data_idx].miso) and (end_idx >= data_idx):
            data_idx += 1

        # TODO verify rest of bytes

        if (data_idx > end_idx):
            raise Exception("Slave did not respond to read command with data")
        else:
            self.addr_bitsize = (data_idx - 1) if fastread else data_idx
            print("Data returned at index {}, using {}-bit address size"
                    .format(data_idx, (self.addr_bitsize * 8)))
            self.cursor += self.addr_bitsize + 1

    def read_memory_block(self):

        if (0x03 != self.stream[self.cursor].mosi):
            return None

        self.cursor += 1

        addr = self.parse_address()
        data = []
        while (0x00 == self.stream[self.cursor].mosi):
            data.append(self.stream[self.cursor].miso)
            self.cursor += 1

        # if (0 != (len(data) % 4)):
        #     print("WARNING: Number of bytes read was not a multiple of 4 ({})".format(len(data)))

        return SpiReadBlock(addr, data)

    def parse_address(self):
        addr_bytes = self.stream[self.cursor : self.cursor + 3]
        addr = (addr_bytes[0].mosi   << 16 
                | addr_bytes[1].mosi << 8
                | addr_bytes[2].mosi)

        if ((0xFF != addr_bytes[0].miso) or
            (0xFF != addr_bytes[1].miso) or
            (0xFF != addr_bytes[2].miso)):
            raise Exception("Slave sent byte during SPI Read Addr")
        
        self.cursor += 3
        return addr

    def handle_block(self, block):

        if STATE_PROCESS_HEADER == self.state:
            self.header = self.parse_header(block)
            if (self.header is None):
                return

            if (self.header.validate()):
                print(self.header)
                if (self.header.block_code & BFLAG_IGNORE):
                    print("Ignoring block...")
                    return

                elif (self.header.block_code & BFLAG_FILL):
                    self.apply_fill()

                else:
                    self.state = STATE_COPY_DATA
            
            else:
                print("Header is invalid")
                raise RuntimeError

            for byte in block.data:
                self.loader_file.write(byte.to_bytes())

        elif STATE_COPY_DATA == self.state:

            self.copy_data()
            self.state = STATE_PROCESS_HEADER

            for byte in block.data[0:self.header.byte_count]:
                self.loader_file.write(byte.to_bytes())
    
    def parse_header(self, block):
        if (16 == len(block.data)):
            return StreamBlockHeader(block.data)

        elif (8 == len(block.data)):
            for byte in block.data:
                self.header_buf.append(byte)
            if (16 == len(self.header_buf)):
                header = StreamBlockHeader(self.header_buf)
                self.header_buf.clear()
                return header
            elif (16 < len(self.header_buf)):
                raise RuntimeError
        else:
            raise RuntimeError

    def apply_fill(self):

        if (self.header.is_within_SRAM()):
            print("Filling {} bytes in SRAM at 0x{:08X}"
                .format(self.header.byte_count, self.header.target_address))
            self.data_file.seek(self.header.target_address - 0xFF800000, 0)
            for idx in range(0, self.header.byte_count):
                self.data_file.write(int(self.header.argument).to_bytes())

        elif (self.header.is_within_bootrom()):
            print("Filling {} bytes in Boot ROM at 0x{:08X}"
                .format(self.header.byte_count, self.header.target_address))
            self.instruction_file.seek(self.header.target_address - 0xFFA00000, 0)
            for idx in range(0, self.header.byte_count):
                self.instruction_file.write(int(self.header.argument).to_bytes())

        else:
            raise RuntimeError
    
    def copy_data(self):

        if (self.header.is_within_SRAM()):
            print("Copying {} bytes to SRAM at 0x{:08X}"
                .format(self.header.byte_count, self.header.target_address))
            self.data_file.seek(self.header.target_address - 0xFF800000, 0)
            for byte in block.data[0:self.header.byte_count]:
                self.data_file.write(byte.to_bytes())

        elif (self.header.is_within_bootrom()):
            print("Copying {} bytes to Boot ROM at 0x{:08X}"
                .format(self.header.byte_count, self.header.target_address))
            self.instruction_file.seek(self.header.target_address - 0xFFA00000, 0)
            for byte in block.data[0:self.header.byte_count]:
                self.instruction_file.write(byte.to_bytes())

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

    def __init__(self, raw):
        self.block_code = int.from_bytes(reversed(raw[0:4]))
        self.target_address = int.from_bytes(reversed(raw[4:8]))
        self.byte_count = int.from_bytes(reversed(raw[8:12]))
        self.argument = int.from_bytes(reversed(raw[12:16]))

    def __str__(self):
        return ("Block Code:\t{:08X}\nTarget Address:\t{:08X}\nByte Count:\t{:08X}\nArgument:\t{:08X}"
                    .format(self.block_code, self.target_address, self.byte_count, self.argument))
    
    def validate(self):

        # TODO Check CRC

        return (HDRSGN == (self.block_code & HDRSGN_MASK))

    def is_within_SRAM(self):
        return (self.target_address >= 0xFF800000) and \
                ((self.target_address + self.byte_count) <= 0xFF807FFF)
    
    def is_within_bootrom(self):
        return (self.target_address >= 0xFFA00000) and \
                ((self.target_address + self.byte_count) <= 0xFFA07FFF)

parser = BootstreamParser(sys.argv[1], )
parser.detect_address_size()

block_ctr = 0
block = parser.read_memory_block()
while block:
    print("{} ".format(block_ctr) + str(block))
    parser.handle_block(block)
    block = parser.read_memory_block()
    block_ctr += 1
