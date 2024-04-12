import ctypes
import gdb
import enum
import math
from typing import Type, Generator
from functools import lru_cache
import gdb
import pwndbg
import argparse
import string

"""Copy pasted from gef because im lazy / forgot how to do with pwndbg"""
def is_hex(pattern: str) -> bool:
    """Return whether provided string is a hexadecimal value."""
    if not pattern.lower().startswith("0x"):
        return False
    return len(pattern) % 2 == 0 and all(c in string.hexdigits for c in pattern[2:])


def parse_address(address: str) -> int:
    """Parse an address and return it as an Integer."""
    if is_hex(address):
        return int(address, 16)
    return int(gdb.parse_and_eval(address))


class Color:
    """Used to colorify terminal output."""
    colors = {
        "normal"         : "\033[0m",
        "gray"           : "\033[1;38;5;240m",
        "light_gray"     : "\033[0;37m",
        "red"            : "\033[31m",
        "green"          : "\033[32m",
        "yellow"         : "\033[33m",
        "blue"           : "\033[34m",
        "pink"           : "\033[35m",
        "cyan"           : "\033[36m",
        "bold"           : "\033[1m",
        "underline"      : "\033[4m",
        "underline_off"  : "\033[24m",
        "highlight"      : "\033[3m",
        "highlight_off"  : "\033[23m",
        "blink"          : "\033[5m",
        "blink_off"      : "\033[25m",
    }

    @staticmethod
    def redify(msg: str) -> str:        return Color.colorify(msg, "red")
    @staticmethod
    def greenify(msg: str) -> str:      return Color.colorify(msg, "green")
    @staticmethod
    def blueify(msg: str) -> str:       return Color.colorify(msg, "blue")
    @staticmethod
    def yellowify(msg: str) -> str:     return Color.colorify(msg, "yellow")
    @staticmethod
    def grayify(msg: str) -> str:       return Color.colorify(msg, "gray")
    @staticmethod
    def light_grayify(msg: str) -> str: return Color.colorify(msg, "light_gray")
    @staticmethod
    def pinkify(msg: str) -> str:       return Color.colorify(msg, "pink")
    @staticmethod
    def cyanify(msg: str) -> str:       return Color.colorify(msg, "cyan")
    @staticmethod
    def boldify(msg: str) -> str:       return Color.colorify(msg, "bold")
    @staticmethod
    def underlinify(msg: str) -> str:   return Color.colorify(msg, "underline")
    @staticmethod
    def highlightify(msg: str) -> str:  return Color.colorify(msg, "highlight")
    @staticmethod
    def blinkify(msg: str) -> str:      return Color.colorify(msg, "blink")

    @staticmethod
    def colorify(text: str, attrs: str) -> str:
        """Color text according to the given attributes."""

        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(str(text))
        if colors["highlight"] in msg:   msg.append(colors["highlight_off"])
        if colors["underline"] in msg:   msg.append(colors["underline_off"])
        if colors["blink"] in msg:       msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)



class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

SCUDO_REGION_INFO_ARRAY_DEFAULT_NAME = "RegionInfoArray"
SCUDO_CACHE_LINE_SIZE = 64

class Config(metaclass=Singleton):
    max_num_cached_hint = -1
    num_classes = -1
    max_size = -1
    largest_class_id = -1
    batch_class_id = -1
    class_size_list = []
    min_alignment = 1 << 4
    primary_compact_ptr_scale = 0
    compact_pointer = ctypes.c_uint64

    def __init__(self):
        bit64 = pwndbg.gdblib.arch.ptrsize == 8
        min_alignment = (4 if bit64 else 3)
        compact_pointer = ctypes.c_uint64 if bit64 else ctypes.c_uint32
        try:
            gdb.parse_and_eval(f"scudo::DefaultConfig")
        except gdb.error as e:
            if "Cannot look up value of a typedef" in str(e):
                min_size_log = 5
                mid_size_log = 8
                max_size_log = 17
                num_bits = 3
                self.max_num_cached_hint = 14
                max_bytes_cached_log = 10
                size_delta = 0
                mid_class = int((1 << mid_size_log) / (1 << min_size_log))

                S = num_bits - 1
                M = (1 << S) - 1
                self.max_size = (1 << max_size_log) + size_delta
                self.num_classes = mid_class + ((max_size_log - mid_size_log) << S) + 1
                self.largest_class_id = self.num_classes - 1
                self.batch_class_id = 0

                for i in range(self.num_classes):
                    if i == 0:
                        self.class_size_list += [-1]
                        continue
                    if i <= mid_class:
                        self.class_size_list += [(i << min_size_log) + size_delta]
                        continue

                    cid = i - mid_class
                    T = (1 << mid_size_log) << (cid >> S)

                    self.class_size_list += [T + (T >> S) * (cid & M) + size_delta]

            else:
                # try:
                #     gdb.parse_and_eval(f"scudo::AndroidConfig")
                # except gdb.error as e:
                #     if "Cannot look up value of a typedef" in str(e):
                min_size_log = 4
                mid_size_log = 6 if bit64 else 7
                max_size_log = 16
                num_bits = 7 if bit64 else 8
                self.max_num_cached_hint = 13 if bit64 else 14
                max_bytes_cached_log = 13
                size_delta = 16

                self.class_size_list = ([-1, 0x00020, 0x00030, 0x00040, 0x00050,
                                         0x00060, 0x00070, 0x00090, 0x000b0, 0x000c0,
                                         0x000e0, 0x00120, 0x00160, 0x001c0, 0x00250,
                                         0x00320, 0x00450, 0x00670, 0x00830, 0x00a10,
                                         0x00c30, 0x01010, 0x01210, 0x01bd0, 0x02210,
                                         0x02d90, 0x03790, 0x04010, 0x04810, 0x05a10,
                                         0x07310, 0x08210, 0x10010,] if bit64 else
                                        [-1, 0x00020, 0x00040, 0x00050, 0x00060,
                                         0x00070, 0x00080, 0x00090, 0x000a0, 0x000b0,
                                         0x000c0, 0x000e0, 0x000f0, 0x00110, 0x00120,
                                         0x00130, 0x00150, 0x00160, 0x00170, 0x00190,
                                         0x001d0, 0x00210, 0x00240, 0x002a0, 0x00330,
                                         0x00370, 0x003a0, 0x00400, 0x00430, 0x004a0,
                                         0x00530, 0x00610, 0x00730, 0x00840, 0x00910,
                                         0x009c0, 0x00a60, 0x00b10, 0x00ca0, 0x00e00,
                                         0x00fb0, 0x01030, 0x01130, 0x011f0, 0x01490,
                                         0x01650, 0x01930, 0x02010, 0x02190, 0x02490,
                                         0x02850, 0x02d50, 0x03010, 0x03210, 0x03c90,
                                         0x04090, 0x04510, 0x04810, 0x05c10, 0x06f10,
                                         0x07310, 0x08010, 0x0c010, 0x10010,])

                self.num_classes = len(self.class_size_list) - 1
                self.largest_class_id = self.num_classes - 1
                self.batch_class_id = 0
                self.max_size = self.class_size_list[-1]
                self.compact_pointer = ctypes.c_uint32
                if bit64:
                    self.primary_compact_ptr_scale = self.min_alignment


def decompact_pointer(class_id, compact_ptr) -> int:
    region_info = ScudoRegionInfo(f"{search_for_scudo_regtion_info()}+{ctypes.sizeof(ScudoRegionInfo.region_info_t())*class_id}")

    config = Config()

    return region_info.region_beg + (compact_ptr << config.primary_compact_ptr_scale)


class ScudoChunk:
    """Scudo chunk class. The default behavior (from_base=False) is to interpret the data starting at the memory
    address pointed to as the chunk data. Setting from_base to True instead treats that data as the chunk header.
    Ref:  https://un1fuzz.github.io/articles, https://llvm.org/docs/ScudoHardenedAllocator.html"""

    class ChunkState(enum.Enum):
        Available = 0
        Allocated = 1
        Quarantined = 2

        def __str__(self) -> str:
            if (self == self.Available):
                return Color.greenify("Available")
            if (self == self.Allocated):
                return Color.yellowify("Allocated")
            if (self == self.Quarantined):
                return Color.redify("Quarantined")
            return f"Invalid Chunk state: {self.value}"

    class ChunkOrigin(enum.Enum):
        Malloc = 0
        New = 1
        NewArray = 2
        Memalign = 3

        def __str__(self) -> str:
            return self.name

    @staticmethod
    def malloc_chunk_t() -> Type[ctypes.Structure]:
        sizetype = ctypes.c_uint32
        pointertype = ctypes.c_uint16
        class malloc_chunk_cls(ctypes.Structure):
            pass

        malloc_chunk_cls._fields_ = [
            ("size", sizetype),
            ("offset", pointertype),
            ("checksum", pointertype),
        ]
        return malloc_chunk_cls

    def __init__(self, addr: int, from_base: bool = False, allow_unaligned: bool = True) -> None:
        ptrsize = pwndbg.gdblib.arch.ptrsize
        hdrsize = 16
        self.data_address = addr + hdrsize if from_base else addr
        self.base_address = addr if from_base else addr - hdrsize
        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoChunk.malloc_chunk_t())
        self._data = pwndbg.gdblib.memory.read(
            self.base_address, ctypes.sizeof(ScudoChunk.malloc_chunk_t()))
        self._chunk = ScudoChunk.malloc_chunk_t().from_buffer_copy(self._data)
        return

    @property
    def size(self) -> int:
        return (self._chunk.size >> 12)

    @property
    def offset(self) -> int:
        return self._chunk.offset

    @property
    def checksum(self) -> int:
        return self._chunk.checksum

    @property
    def state(self) -> ChunkState:
        return ScudoChunk.ChunkState((self._chunk.size >> 8) & 0x3)

    @property
    def origin(self) -> ChunkOrigin:
        return ScudoChunk.ChunkOrigin((self._chunk.size >> 10) & 0x3)

    @property
    def classid(self) -> int:
        return self._chunk.size & 0xff

    @property
    def was_zeroed(self) -> bool:
        return self.origin and self.state != ScudoChunk.ChunkState.Allocated

    def __str_extended(self) -> str:
        msg = []
        failed = False

        try:
            if self.state == ScudoChunk.ChunkState.Available:
                msg.append("Was zeroed: {0!r}".format(self.origin == ScudoChunk.ChunkOrigin.Malloc))
            else:
                msg.append("Origin: {0!s}".format(self.origin))
            msg.append("Chunk size: {0:d} ({0:#x})".format(self.size))
            msg.append("Offset: {0:d} ({0:#x})".format(self.offset))
            msg.append("Checksum: {0:#x}".format(self.checksum))
            failed = True
        except gdb.MemoryError:
            msg.append(f"Chunk size: Cannot read at {self.size_addr:#x} (corrupted?)")

        if failed:
            msg.append(str(self.state))

        return "\n".join(msg)

    def __str__(self) -> str:
        return (f"{Color.colorify('Chunk', 'yellow bold underline')}(addr={self.data_address:#x}, "
                f"size={self.size:#x}, state={self.state!s}, classid={self.classid})")

    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"

@lru_cache()
def search_for_scudo_region_info() -> int:
    """A helper function to find the scudo `RegionInfoArray` address, either from symbol or from its offset
    from `Allocator`."""
    try:
        addr = parse_address(f"&{SCUDO_REGION_INFO_ARRAY_DEFAULT_NAME}")

    except gdb.error:
        allocator_addr = parse_address("(void *)&Allocator")

        addr = allocator_addr + 192

    return addr

@lru_cache()
def search_for_scudo_per_class_array(thread_id) -> int:
    """A helper function to find the scudo `PerClassArray` address, from `Allocator`."""

    try:
        addr = parse_address("(void *)&(Allocator.TSDRegistry.ThreadTSD.Cache.PerClassArray)")
    except gdb.error:
        stats_addr = parse_address("*(((void**)&Allocator)+8)")
        for i in range(thread_id+1):
            stats_addr = parse_address(f"*((void**){stats_addr:#x})")
        addr = parse_address(f"(void*){stats_addr:#x}-{ScudoPerClass.array_size_offset()*Config().num_classes}")
    return addr

@lru_cache()
def search_for_scudo_large_block() -> int:
    """A helper function to find the scudo `LargeBlock` address of the first element of the linked list of used blocks from `Allocator`."""

    try:
        addr = parse_address("Allocator.Secondary.InUseBlocks.First")
    except gdb.error:
        addr = parse_address("*(*(((void***)&Allocator)+8)-6)")

    return addr

@lru_cache()
def search_for_scudo_large_block_cache() -> int:
    """A helper function to find the address of the first element of the list of cached secondary blocks."""

    try:
        addr = parse_address("&Allocator.Secondary.Cache.Entries")
    except gdb.error:
        addr = parse_address("((void*)&Allocator)+0x22a8")

    return addr


class ScudoRegionInfo:
    """Scudo region info class"""

    @staticmethod
    def region_info_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if pwndbg.gdblib.arch.ptrsize == 8 else ctypes.c_uint32
        config = Config()
        fields = [
            ("mutex", ctypes.c_uint32),
            ("freelist_size", pointer),
            ("freelist_first", pointer),
            ("freelist_last", pointer),
            ("region_beg", pointer),
            ("popped_blocks", pointer),
            ("pushed_blocks", pointer),
            ("rand_state", ctypes.c_uint32),
            ("mapped_user", pointer),
            ("allocated_user", pointer),
            ("data", ctypes.c_uint8),
            ("release_last_pushed_blocks", pointer),
            ("release_ranges", pointer),
            ("release_last_bytes", pointer),
            ("release_last_at_ns", ctypes.c_uint64),
            ("exhausted", ctypes.c_uint8),
        ]

        class unpadded_region_info_cls(ctypes.Structure):
            _fields_ = fields

        fields += [("padding", (SCUDO_CACHE_LINE_SIZE - (ctypes.sizeof(unpadded_region_info_cls) % SCUDO_CACHE_LINE_SIZE)) * ctypes.c_char)]

        class region_info_cls(ctypes.Structure):
            _fields_ = fields
        return region_info_cls

    def __init__(self, addr: str) -> None:
        try:
            self.__address : int = parse_address(f"{addr}")
        except gdb.error:
            self.__address : int = search_for_scudo_region_info()
            # if `search_for_scudo_region_info` throws `gdb.error` on symbol lookup:
            # it means the session is not started, so just propagate the exception
        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoRegionInfo.region_info_t())
        self._data = pwndbg.gdblib.memory.read(self.__address, ctypes.sizeof(ScudoRegionInfo.region_info_t()))
        self.__region = ScudoRegionInfo.region_info_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def num_free(self) -> int:
        return self.__region.freelist_size

    @property
    def first_free(self) -> int:
        return self.__region.freelist_first

    @property
    def last_free(self) -> int:
        return self.__region.freelist_last

    @property
    def region_beg(self) -> int:
        return self.__region.region_beg

    @property
    def popped_blocks(self) -> int:
        return self.__region.popped_blocks

    @property
    def pushed_blocks(self) -> int:
        return self.__region.pushed_blocks

    @property
    def rand_state(self) -> int:
        return self.__region.rand_state

    @property
    def mapped_user(self) -> int:
        return self.__region.mapped_user

    @property
    def allocated_user(self) -> int:
        return self.__region.allocated_user

    @property
    def pushed_blocks_at_last_release(self) -> int:
        return self.__region.release_last_pushed_blocks

    @property
    def ranges_released(self) -> int:
        return self.__region.release_ranges

    @property
    def last_released_bytes(self) -> int:
        return self.__region.release_last_bytes

    @property
    def last_release_at_ns(self) -> int:
        return self.__region.release_last_at_ns

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, region_begin={self.region_beg:#x}, " \
                f"mapped={self.mapped_user:#x}, allocated={self.allocated_user:#x}, " \
                f"num_batches={self.num_free:d}"
        return (f"{Color.colorify('Region', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"ScudoRegionInfo(address={self.__address:#x}, size={self._sizeof})"

    def __str_extended(self) -> str:
        msg = []
        failed = False

        msg.append("Free list (BatchGroup):")
        msg.append("\tNumber free: {0:d}".format(self.num_free))
        msg.append("\tFirst free: {0:#x}".format(self.first_free))
        msg.append("\tLast free: {0:#x}".format(self.last_free))

        msg.append("\nRegion stats:")
        msg.append("\tPopped blocks: {0:d}".format(self.popped_blocks))
        msg.append("\tPushed blocks: {0:d}".format(self.pushed_blocks))

        msg.append("\nRandom state: {0:d}".format(self.rand_state))

        msg.append("\nRelease to OS:")
        msg.append("\tPushed blocks at last release: {0:#x}".format(self.pushed_blocks_at_last_release))
        msg.append("\tRanges released: {0:#x}".format(self.ranges_released))
        msg.append("\tLast released bytes: {0:#x}".format(self.last_released_bytes))
        msg.append("\tLast release at ns: {0:d}".format(self.last_release_at_ns))

        return "\n".join(msg)

    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"


class ScudoBatchGroup:
    """Scudo batch group class"""

    @staticmethod
    def batch_group_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if pwndbg.gdblib.arch.ptrsize == 8 else ctypes.c_uint32
        fields = [
            ("next", pointer),
            ("compact_ptr_group_base", pointer),
            ("max_cached_per_batch", ctypes.c_uint16),
            ("pushed_blocks", pointer),
            ("pushed_blocks_at_last_checkpoint", pointer),
            ("batches_size", pointer),
            ("batches_first", pointer),
            ("batches_last", pointer),
        ]

        class batch_group_cls(ctypes.Structure):
            _fields_ = fields
        return batch_group_cls

    def __init__(self, addr: str) -> None:
        self.__address : int = parse_address(f"{addr}")

        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoBatchGroup.batch_group_t())
        self._data = pwndbg.gdblib.memory.read(self.__address, ctypes.sizeof(ScudoBatchGroup.batch_group_t()))
        self.__batch_group = ScudoBatchGroup.batch_group_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def num_batches(self) -> int:
        return self.__batch_group.batches_size

    @property
    def first_batch(self) -> int:
        return self.__batch_group.batches_first

    @property
    def last_batch(self) -> int:
        return self.__batch_group.batches_last

    @property
    def compact_ptr_group_base(self) -> int:
        return self.__batch_group.compact_ptr_group_base

    @property
    def max_cached_per_batch(self) -> int:
        return self.__batch_group.max_cached_per_batch

    @property
    def pushed_blocks(self) -> int:
        return self.__batch_group.pushed_blocks

    @property
    def pushed_blocks_at_last_checkpoint(self) -> int:
        return self.__batch_group.pushed_blocks_at_last_checkpoint

    @property
    def next_addr(self) -> int:
        return self.__batch_group.next

    def get_next_batch_group(self) -> "ScudoBatchGroup":
        addr = self.next_addr
        return ScudoBatchGroup(addr)

    def __iter__(self) -> Generator["ScudoBatchGroup", None, None]:
        current_group = self

        while current_group.next_addr:
            yield current_group

            next_group_addr = current_group.next_addr()

            if not Address(value=next_group_addr).valid:
                break

            next_group = current_group.get_next_batch_group()
            if next_group is None:
                break
            current_group = next_group
        return

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, num_batches={self.num_batches:d}, " \
                f"first_batch={self.first_batch:#x}, pushed_blocks={self.pushed_blocks:d}"
        return (f"{Color.colorify('BatchGroup', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"BatchGroup(address={self.__address:#x}, size={self._sizeof})"

    def __str_extended(self) -> str:
        msg = []

        msg.append("Next batch group: {0:#x}".format(self.next_addr))
        msg.append("Compact base addr: {0:#x}".format(self.compact_ptr_group_base))

        msg.append("Max cached per batch: {0:d}".format(self.max_cached_per_batch))

        msg.append("Pushed blocks: {0:d}".format(self.pushed_blocks))
        msg.append("Pushed blocks at last checkpoint: {0:d}".format(self.pushed_blocks_at_last_checkpoint))

        msg.append("Batches (TransferBatch):")
        msg.append("\tNumber batches: {0:d}".format(self.num_batches))
        msg.append("\tFirst batch: {0:#x}".format(self.first_batch))
        msg.append("\tLast last: {0:#x}".format(self.last_batch))

        return "\n".join(msg)

    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"

class ScudoTransferBatch:
    """Scudo transfer batch class"""

    @staticmethod
    def transfer_batch_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if pwndbg.gdblib.arch.ptrsize == 8 else ctypes.c_uint32
        config = Config()
        fields = [
            ("next", pointer),
            ("batches", config.max_num_cached_hint*config.compact_pointer),
            ("count", ctypes.c_uint16),
        ]

        class transfer_batch_cls(ctypes.Structure):
            _fields_ = fields
        return transfer_batch_cls

    def __init__(self, addr: str) -> None:
        self.__address : int = parse_address(f"{addr}")

        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoTransferBatch.transfer_batch_t())
        self._data = pwndbg.gdblib.memory.read(self.__address, ctypes.sizeof(ScudoTransferBatch.transfer_batch_t()))
        self.__transfer_batch = ScudoTransferBatch.transfer_batch_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def count(self) -> int:
        return self.__transfer_batch.count

    @property
    def batches(self) -> [int]:
        return self.__transfer_batch.batches

    @property
    def next_addr(self) -> int:
        return self.__transfer_batch.next

    def get_next_transfer_batch(self) -> "ScudoTransferBatch":
        addr = self.next_addr
        return ScudoTransferBatch(addr)

    def __iter__(self) -> Generator["ScudoTransferBatch", None, None]:
        current_tb = self

        while current_tb.next_addr:
            yield current_tb

            next_tb_addr = current_tb.next_addr()

            if not Address(value=next_tb_addr).valid:
                break

            next_tb= current_tb.get_next_transfer_batch()
            if next_tb is None:
                break
            current_tb = next_tb
        return

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, num_batches={self.count:d}"
        return (f"{Color.colorify('TransferBatch', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"TransferBatch(address={self.__address:#x}, size={self._sizeof})"

    def __str_extended(self) -> str:
        msg = []

        msg.append("Next transfer batch: {0:#x}".format(self.next_addr))
        msg.append("Number batches: {0:d}".format(self.count))

        for _i in range(self.count):
            msg.append("\tBatch #{0:d}: {1:#x}".format(_i, self.batches[_i]))

        return "\n".join(msg)

    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"

class ScudoPerClass:
    """Scudo per class cache"""

    @staticmethod
    def per_class_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if pwndbg.gdblib.arch.ptrsize == 8 else ctypes.c_uint32
        config = Config()
        fields = [
            ("count", ctypes.c_uint16),
            ("max_count", ctypes.c_uint16),
            ("class_size", pointer),
            ("chunks", 2*config.max_num_cached_hint*config.compact_pointer),
        ]

        class per_class_cls(ctypes.Structure):
            _fields_ = fields
        return per_class_cls

    @staticmethod
    def array_size_offset() -> int:
        class_size = ctypes.sizeof(ScudoPerClass.per_class_t())


        return SCUDO_CACHE_LINE_SIZE * math.ceil(class_size / SCUDO_CACHE_LINE_SIZE)

    def __init__(self, addr: str) -> None:
        self.__address : int = parse_address(f"{addr}")

        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoPerClass.per_class_t())
        self._data = pwndbg.gdblib.memory.read(self.__address, ctypes.sizeof(ScudoPerClass.per_class_t()))
        self.__per_class = ScudoPerClass.per_class_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def count(self) -> int:
        return self.__per_class.count

    @property
    def max_count(self) -> int:
        return self.__per_class.max_count

    @property
    def class_size(self) -> int:
        return self.__per_class.class_size

    @property
    def chunks(self) -> [int]:
        return self.__per_class.chunks

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, count={self.count:d}"
        return (f"{Color.colorify('PerClass', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"PerClass(address={self.__address:#x}, size={self._sizeof})"

    def __str_extended(self) -> str:
        msg = []

        msg.append("Number chunks: {0:d}".format(self.count))
        msg.append("Maximal number chunks: {0:d}".format(self.max_count))
        msg.append("Class size: {0:d}".format(self.class_size))

        for _i in range(self.count):
            if len(self.chunks) <= _i:
                msg.append("\t!Invalid length of buffer!")
                break
            msg.append("\tChunk #{0:d}: {1:#x}".format(_i, self.chunks[_i]))

        return "\n".join(msg)

    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"

class ScudoLargeBlock:
    """Scudo large block class"""

    @staticmethod
    def large_block_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if pwndbg.gdblib.arch.ptrsize == 8 else ctypes.c_uint32
        fields = [
            ("prev", pointer),
            ("next", pointer),
            ("commit_base", pointer),
            ("commit_size", pointer),
            ("map_base", pointer),
            ("map_size", pointer),
            ("data", ctypes.c_uint8),
        ]

        class large_block_cls(ctypes.Structure):
            _fields_ = fields
        return large_block_cls

    def __init__(self, addr: str, from_base: bool = True) -> None:
        self.__address : int = parse_address(f"{addr}")
        if not from_base:
            self.__address -= ctypes.sizeof(ScudoLargeBlock.large_block_t())
            self.__address -= ctypes.sizeof(ScudoChunk.malloc_chunk_t())

        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoLargeBlock.large_block_t())
        self._data = pwndbg.gdblib.memory.read(self.__address, ctypes.sizeof(ScudoLargeBlock.large_block_t()))
        self.__large_block = ScudoLargeBlock.large_block_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def commit_base(self) -> int:
        return self.__large_block.commit_base

    @property
    def commit_size(self) -> int:
        return self.__large_block.commit_size

    @property
    def map_base(self) -> int:
        return self.__large_block.map_base

    @property
    def map_size(self) -> int:
        return self.__large_block.map_size

    @property
    def data(self) -> int:
        return self.__large_block.data

    @property
    def next_addr(self) -> int:
        return self.__large_block.next

    def get_next_large_block(self) -> "ScudoLargeBlock":
        addr = self.next_addr
        return ScudoLargeBlock(addr)

    @property
    def prev_addr(self) -> int:
        return self.__large_block.prev

    def get_prev_large_block(self) -> "ScudoLargeBlock":
        addr = self.prev_addr
        return ScudoLargeBlock(addr)

    def __iter__(self) -> Generator["ScudoLargeBlock", None, None]:
        current_block = self

        while current_block.next_addr:
            yield current_block

            next_block_addr = current_block.next_addr()

            if not Address(value=next_block_addr).valid:
                break

            next_block = current_block.get_next_large_block()
            if next_block is None:
                break
            current_block = next_block
        return

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, next={self.next_addr:#x}"
        return (f"{Color.colorify('LargeBlock', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"LargeBlock(address={self.__address:#x}, size={self._sizeof})"

    def __str_extended(self) -> str:
        msg = []

        msg.append("Next large block: {0:#x}".format(self.next_addr))
        msg.append("Previous large block: {0:#x}".format(self.prev_addr))

        msg.append("Commit base: {0:#x}".format(self.commit_base))
        msg.append("Commit size: {0:d}".format(self.commit_size))

        msg.append("Map base: {0:#x}".format(self.map_base))
        msg.append("Map size: {0:d}".format(self.map_size))

        return "\n".join(msg)

    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"

class ScudoCachedBlock:
    """Scudo large block class"""

    @staticmethod
    def cached_block_t() -> Type[ctypes.Structure]:
        pointer = ctypes.c_uint64 if pwndbg.gdblib.arch.ptrsize == 8 else ctypes.c_uint32
        fields = [
            ("commit_base", pointer),
            ("commit_size", pointer),
            ("map_base", pointer),
            ("map_size", pointer),
            ("block_begin", pointer),
            ("time", ctypes.c_uint64),
        ]

        class cached_block_cls(ctypes.Structure):
            _fields_ = fields
        return cached_block_cls

    def __init__(self, addr: str) -> None:
        self.__address : int = parse_address(f"{addr}")

        self.reset()
        return

    def reset(self):
        self._sizeof = ctypes.sizeof(ScudoCachedBlock.cached_block_t())
        self._data = pwndbg.gdblib.memory.read(self.__address, ctypes.sizeof(ScudoCachedBlock.cached_block_t()))
        self.__cached_block = ScudoCachedBlock.cached_block_t().from_buffer_copy(self._data)
        return

    def __abs__(self) -> int:
        return self.__address

    def __int__(self) -> int:
        return self.__address

    @property
    def address(self) -> int:
        return self.__address

    @property
    def sizeof(self) -> int:
        return self._sizeof

    @property
    def addr(self) -> int:
        return int(self)

    @property
    def commit_base(self) -> int:
        return self.__cached_block.commit_base

    @property
    def commit_size(self) -> int:
        return self.__cached_block.commit_size

    @property
    def map_base(self) -> int:
        return self.__cached_block.map_base

    @property
    def map_size(self) -> int:
        return self.__cached_block.map_size

    @property
    def block_begin(self) -> int:
        return self.__cached_block.block_begin

    @property
    def data(self) -> int:
        return self.__cached_block.data

    @property
    def time(self) -> int:
        return self.__cached_block.time

    @property
    def next_addr(self) -> int:
        return self.addr + self.sizeof

    def get_next_cached_block(self) -> "ScudoCachedBlock":
        addr = self.next_addr
        return ScudoCachedBlock(addr)

    @property
    def prev_addr(self) -> int:
        return self.addr - self.sizeof

    def get_prev_cached_block(self) -> "ScudoCachedBlock":
        addr = self.prev_addr
        return ScudoCachedBlock(addr)

    def __iter__(self) -> Generator["ScudoCachedBlock", None, None]:
        current_block = self

        while current_block.next_addr:
            yield current_block

            next_block_addr = current_block.next_addr()

            if not Address(value=next_block_addr).valid:
                break

            next_block = current_block.get_next_cached_block()
            if next_block is None:
                break
            current_block = next_block
        return

    def __str__(self) -> str:
        properties = f"base={self.__address:#x}, map size={self.map_size:#x}"
        return (f"{Color.colorify('LargeCachedBlock', 'blue bold underline')}({properties})")

    def __repr__(self) -> str:
        return f"LargeCachedBlock(address={self.__address:#x}, size={self._sizeof})"

    def __str_extended(self) -> str:
        msg = []

        msg.append("Commit base: {0:#x}".format(self.commit_base))
        msg.append("Commit size: {0:d}".format(self.commit_size))

        msg.append("Map base: {0:#x}".format(self.map_base))
        msg.append("Map size: {0:d}".format(self.map_size))

        msg.append("Block begin: {0:#x}".format(self.block_begin))

        msg.append("Time: {0:#x}".format(self.time))

        return "\n".join(msg)

    def psprint(self) -> str:
        msg = [
            str(self),
            self.__str_extended(),
        ]
        return "\n".join(msg) + "\n"

scudo_setup_parser = argparse.ArgumentParser(description="Base command to get information about the Scudo heap structure.")
scudo_setup_parser.add_argument("--quarantine", action="store_true", help="")
scudo_setup_parser.add_argument("--q-thread-kb", type=int, nargs='?', default=5, help="")
scudo_setup_parser.add_argument("--q-kb", type=int, nargs='?', default=10, help="")
scudo_setup_parser.add_argument("--q-max-chunk", type=int, nargs='?', default=2048, help="")
scudo_setup_parser.add_argument("location", type=str, nargs='?', default=None, help="")

@pwndbg.commands.ArgparsedCommand(scudo_setup_parser)
def scudo_setup(quarantine=False, q_thread_kb=5, q_kb=10, q_max_chunk=2048, location=None):
    if quarantine:
        gdb.execute(f"set environment SCUDO_OPTIONS thread_local_quarantine_size_kb={q_thread_kb}:quarantine_size_kb={q_kb}:quarantine_max_chunk_size={q_max_chunk}")
    if location:
        gdb.execute(f"set environment LD_PRELOAD {location}")


scudo_chunk_parser = argparse.ArgumentParser(description="Display information on a heap chunk.")
scudo_chunk_parser.add_argument("address", type=int)


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.commands.ArgparsedCommand(scudo_chunk_parser)
def scudo_chunk(address):
    current_chunk = ScudoChunk(address)

    print(current_chunk.psprint())


scudo_regions_parser = argparse.ArgumentParser(description="Display information on all the available regions.")

@pwndbg.commands.ArgparsedCommand(scudo_regions_parser)
@pwndbg.commands.OnlyWhenRunning
def scudo_regions():
    region_info_array_base = search_for_scudo_region_info()

    config = Config()

    region_info = [ScudoRegionInfo("")]
    print(str(region_info[0]))

    for i in range(1, config.num_classes):
        addr = parse_address(f"{region_info[0].address}+{ctypes.sizeof(ScudoRegionInfo.region_info_t())*i}")
        region_info += [ScudoRegionInfo(f"{addr:#x}")]
        print(str(region_info[-1]))


scudo_region_parser = argparse.ArgumentParser(description="Display information on a specific region either by index or by address.")
scudo_region_group = scudo_region_parser.add_mutually_exclusive_group(required=True)
scudo_region_group.add_argument("--address", type=int, nargs='?', default=None, help="")
scudo_region_group.add_argument("--num_bytes", type=int, nargs='?', default=None, help="")
scudo_region_group.add_argument("--index", type=int, nargs='?', default=None, help="class_id")

@pwndbg.commands.ArgparsedCommand(scudo_region_parser)
@pwndbg.commands.OnlyWhenRunning
def scudo_region(address=None, num_bytes=None, index=None):
    config = Config()

    region_info_addr = -1
    if address is not None:
        region_info_addr = address
    elif size is not None:
        index = 0
        size = (config.min_alignment * math.ceil(size / config.min_alignment)) + (config.min_alignment * math.ceil(ctypes.sizeof(ScudoChunk.malloc_chunk_t()) / config.min_alignment))
        while index < config.num_classes:
            #print(f"{index}    {config.class_size_list[index]}")
            if size <= config.class_size_list[index]:
                break
            index += 1
        region_info_addr = parse_address(f"{search_for_scudo_region_info()}+{ctypes.sizeof(ScudoRegionInfo.region_info_t())*index}")
    else:
        region_info_addr = parse_address(f"{search_for_scudo_region_info()}+{ctypes.sizeof(ScudoRegionInfo.region_info_t())*index}")

    region_info = ScudoRegionInfo(f"{region_info_addr:#x}")
    print(region_info.psprint())


scudo_batchgroup_parser = argparse.ArgumentParser(description="Display information on a batch group.")
scudo_batchgroup_parser.add_argument("address", type=int, help="")
scudo_batchgroup_parser.add_argument("--number", type=int, nargs='?', default=None, help="")

@pwndbg.commands.ArgparsedCommand(scudo_batchgroup_parser)
@pwndbg.commands.OnlyWhenRunning
def scudo_batchgroup(address, number=None):
    current_group = ScudoBatchGroup(address)

    if number is not None:
        for _i in range(number):
            if current_group.sizeof == 0:
                break

            print(str(current_group))
            next_group_addr = current_group.next_addr
            if not Address(value=next_group_addr).valid:
                break

            next_group = current_group.get_next_batch_group()
            if next_group is None:
                break

            current_group = next_group
    else:
        print(current_group.psprint())


scudo_transferbatch_parser = argparse.ArgumentParser(description="Display information on a transfer batch.")
scudo_transferbatch_parser.add_argument("address", type=int, help="")
scudo_transferbatch_parser.add_argument("--number", type=int, nargs='?', default=None, help="")


@pwndbg.commands.ArgparsedCommand(scudo_transferbatch_parser)
@pwndbg.commands.OnlyWhenRunning
def scudo_transferbatch(address, number=None):
    current_tb = ScudoTransferBatch(address)

    if number is not None:
        for _i in range(number):
            if current_tb.sizeof == 0:
                break

            print(str(current_tb))
            next_tb_addr = current_tb.next_addr
            if not Address(value=next_tb_addr).valid:
                break

            next_tb = current_tb.get_next_transfer_batch()
            if next_tb is None:
                break

            current_tb = next_tb
    else:
        print(current_tb.psprint())

scudo_perclass_parser = argparse.ArgumentParser(description="Display information on a per class structure.")
scudo_perclass_parser.add_argument("thread_index", type=int, help="")
scudo_perclass_parser.add_argument("index", type=int, help="")


@pwndbg.commands.ArgparsedCommand(scudo_perclass_parser)
@pwndbg.commands.OnlyWhenRunning
def scudo_perclass(thread_index, index):
    per_class_addr = parse_address(f"{search_for_scudo_per_class_array(thread_index)}+{ScudoPerClass.array_size_offset()*index}")

    per_class = ScudoPerClass(f"{per_class_addr:#x}")

    print(per_class.psprint())

scudo_largeblock_parser = argparse.ArgumentParser(description="Display information on a large block.")
scudo_largeblock_parser.add_argument("--address", type=int, nargs='?', default=None, help="")
scudo_largeblock_parser.add_argument("--number", type=int, nargs='?', default=None, help="")


@pwndbg.commands.ArgparsedCommand(scudo_largeblock_parser)
@pwndbg.commands.OnlyWhenRunning
def scudo_largeblock(address=None, number=None):
    if address is None:
        addr = search_for_scudo_large_block()
    else:
        addr = address

    current_block = ScudoLargeBlock(addr, from_base = address is None)

    if number > 1:
        for _i in range(number):
            if current_block.sizeof == 0:
                break

            print(str(current_block))
            next_block_addr = current_block.next_addr
            if not Address(value=next_block_addr).valid:
                break

            next_block = current_block.get_next_large_block()
            if next_block is None:
                break

            current_block = next_block
    else:
        print(current_block.psprint())


scudo_largecachedblock_parser = argparse.ArgumentParser(description="Display information on a large block.")
scudo_largecachedblock_parser.add_argument("--address", type=int, nargs='?', default=None, help="")
scudo_largecachedblock_parser.add_argument("--number", type=int, nargs='?', default=None, help="")


@pwndbg.commands.ArgparsedCommand(scudo_largecachedblock_parser)
@pwndbg.commands.OnlyWhenRunning


def scudo_largecachedblock(address=None, number=None):
    if address is None:
        addr = search_for_scudo_large_block_cache()
    else:
        addr = address

    current_block = ScudoCachedBlock(addr)

    if number > 1:
        for _i in range(number):
            if current_block.sizeof == 0:
                break

            print(str(current_block))
            next_block_addr = current_block.next_addr
            if not Address(value=next_block_addr).valid:
                break

            next_block = current_block.get_next_cached_block()
            if next_block is None:
                break

            current_block = next_block
    else:
        print(current_block.psprint())
    return

