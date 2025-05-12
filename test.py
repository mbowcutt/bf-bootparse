"""bootparse.py test script"""

import sys

from bootparse import BootstreamParser, SpiReadBlock, BF59xBlkHdr

parser = BootstreamParser(sys.argv[1])
parser.detect_address_size()
spi_read_blocks = parser.parse_memory_blocks()
parser.build_ldr_file(spi_read_blocks)
bootstream_blk_headers = parser.handle_blocks(spi_read_blocks)

print("SPI Read Blocks:")
SpiReadBlock.print_block_table(spi_read_blocks)
print()
print("Bootstream Headers:")
BF59xBlkHdr.print_header_table(bootstream_blk_headers)
