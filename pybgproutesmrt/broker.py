# SPDX-FileCopyrightText: 2025 Thomas Alfroy
#
# SPDX-License-Identifier: GPL-2.0-only

import requests
import datetime
import json
import os
from requests.exceptions import HTTPError, ConnectionError, Timeout
import ctypes
from ctypes import c_int, c_uint64, c_uint32, c_uint16, c_uint8, c_char, c_void_p, POINTER, Structure
import struct, socket


BGPDUMP_MAX_FILE_LEN	= 1024
BGPDUMP_MAX_AS_PATH_LEN	= 2000
MAX_NB_PREFIXES         = 2048
MAX_ASPATH_ASNS         = 256
MAX_ASPATH_SEGS         = 64
MAX_COMMUNITIES         = 1024
MAX_ATTR                = 4096

BGP_TYPE_ZEBRA_BGP			= 16
BGP_TYPE_ZEBRA_BGP_ET       = 17
BGP_TYPE_TABLE_DUMP_V2      = 13

BGP_SUBTYPE_RIB_IPV4_UNICAST = 2
BGP_SUBTYPE_RIB_IPV6_UNICAST = 4


BGP_TYPE_OPEN               = 1
BGP_TYPE_KEEPALIVE          = 4
BGP_TYPE_UPDATE             = 2
BGP_TYPE_NOTIFICATION       = 3
BGP_TYPE_STATE_CHANGE       = 5


BGPROUTESMRT_LIBRARY_PATH='/usr/local/lib/'


# Import CFRFILE structure from C library
class CFRFILE(Structure):
    _fields_ = [
        ("format", c_int),       # 0 = not open, 1 = uncompressed, 2 = bzip2, 3 = gzip
        ("eof", c_int),          # 0 = not EOF
        ("closed", c_int),       # indicates whether fclose has been called, 0 = not yet
        ("error1", c_int),       # errors from the system, 0 = no error
        ("error2", c_int),       # for error messages from the compressor
        ("data1", c_void_p), # system file handle (FILE *)
        ("data2", c_void_p),     # additional handle(s) for the compressor
        ("bz2_stream_end", c_int) # True when a bz2 stream has ended
    ]


# Import RIB_PEER_INDEX structure from C library
class RIB_PEER_INDEX_T(Structure):
    _fields_ = [
        ("afi", c_int),
        ("idx", c_int),
        ("addr1", c_uint64),
        ("addr0", c_uint64),
        ("asn", c_uint32)
    ]


class FILE_BUF_T(Structure):
    _fields_ = [
        ("f", POINTER(CFRFILE)),  # Pointer to CFRFILE
        ("f_type", c_int),        # Integer representing the file type
        ("eof", c_int),           # End of file flag
        ("filename", c_char * BGPDUMP_MAX_FILE_LEN),  # Filename array of length BGPDUMP_MAX_FILE_LEN
        ("parsed", c_int),        # Indicates if the file is parsed
        ("parsed_ok", c_int),     # Indicates if the parsing was successful
        ("index", RIB_PEER_INDEX_T * 256),
        ("actPeerIdx", c_int),
        ("actEntry", ctypes.c_void_p)
    ]


class MRT_ENTRY(Structure):
    _fields_ = [
        ("entryType", c_uint16),
        ("entrySubType", c_uint16),
        ("entryLength", c_uint32),

        ("bgpType", c_uint16),

        ("peer_asn", c_uint32),
        ("afi", c_uint16),

        ("peer_address1", c_uint64),
        ("peer_address0", c_uint64),

        ("time", c_uint32),
        ("time_ms", c_uint32),

        ("nbWithdraw", c_uint16),
        ("nbNLRI", c_uint16),

        ("withdraw_address1", c_uint64 * MAX_NB_PREFIXES),
        ("withdraw_address0", c_uint64 * MAX_NB_PREFIXES),
        ("withdraw_prefix_len", c_uint8 * MAX_NB_PREFIXES),

        ("nlri_address1", c_uint64 * MAX_NB_PREFIXES),
        ("nlri_address0", c_uint64 * MAX_NB_PREFIXES),
        ("nlri_prefix_len", c_uint8 * MAX_NB_PREFIXES),

        ("nextHop_address1", c_uint64),
        ("nextHop_address0", c_uint64),

        ("asPathLen", c_uint8),
        ("asPathSegCount", c_uint8),
        ("asPath", c_uint32 * MAX_ASPATH_ASNS),

        ("asPathSegOffset", c_uint8 * MAX_ASPATH_SEGS),
        ("asPathSegType", c_uint8 * MAX_ASPATH_SEGS),
        ("asPathSegLen", c_uint8 * MAX_ASPATH_SEGS),

        ("communities_count", c_uint16),
        ("communities_attr_type", c_uint8 * MAX_COMMUNITIES),
        ("communities_value_len", c_uint8 * MAX_COMMUNITIES),
        ("communities1", c_uint64 * MAX_COMMUNITIES),
        ("communities0", c_uint64 * MAX_COMMUNITIES),

        ("origin", c_uint8),
        ("origin_present", c_uint8),

        ("dumper", POINTER(FILE_BUF_T)),
        ("next", c_void_p),
        ("prev", c_void_p),
    ]



def _u128_to_ip(addr1: int, addr0: int) -> str:
    """Convert (address1,address0) into a printable IP string.
    Convention: IPv4 iff addr1 == 0, and IPv4 is stored in low 32 bits of addr0.
    """
    if addr1 == 0:
        v4 = addr0 & 0xFFFFFFFF
        return socket.inet_ntop(socket.AF_INET, struct.pack("!I", v4))
    else:
        b = addr1.to_bytes(8, "big") + addr0.to_bytes(8, "big")
        return socket.inet_ntop(socket.AF_INET6, b)

def _prefix_to_str(addr1: int, addr0: int, plen: int) -> str:
    return f"{_u128_to_ip(addr1, addr0)}/{int(plen)}"

def _decode_origin(code: int) -> str:
    # standard: 0=IGP, 1=EGP, 2=INCOMPLETE
    if code == 0:
        return "IGP"
    if code == 1:
        return "EGP"
    if code == 2:
        return "INCOMPLETE"
    return str(int(code))

def _classic_comm_to_str(v: int) -> str:
    # v is 32-bit packed (asn16<<16 | val16) placed in communities0, communities1=0
    asn = (v >> 16) & 0xFFFF
    val = v & 0xFFFF
    return f"{asn}:{val}"

class BGPmessage:
    """
    Structure that represents a BGP message parsed from an MRT entry.

    This class is a thin Python wrapper around a native MRTentry structure.
    All protocol fields are stored in native, non-string form (integers and
    integer arrays). Human-readable string representations are derived
    on demand via helper properties.

    Attributes:
        ts (float):
            UNIX timestamp at which the BGP message was collected by the
            vantage point (seconds + fractional microseconds).

        type (int):
            MRT entry type (e.g., BGP4MP, BGP4MP_ET, TABLE_DUMP_V2).

        bgpType (int):
            Numeric BGP message type (e.g., UPDATE, OPEN, KEEPALIVE,
            NOTIFICATION, STATE_CHANGE).

        msgType (str):
            Single-character message code derived from bgpType:
            'U' (UPDATE), 'O' (OPEN), 'K' (KEEPALIVE),
            'N' (NOTIFICATION), 'S' (STATE_CHANGE), 'R' (RIB entry).

        peer_asn (int):
            Autonomous System Number (ASN) of the BGP peer from which
            the message was received.

        peer_addr (tuple[int, int]):
            BGP peer IP address stored as a split 128-bit integer
            (address1, address0). IPv4 addresses are represented with
            address1 == 0 and address0 holding the IPv4 value.

        nlri (list[tuple[int, int, int]]):
            List of announced prefixes in native form.
            Each prefix is represented as:
                (address1, address0, prefix_len)

        withdraws (list[tuple[int, int, int]]):
            List of withdrawn prefixes in native form.
            Each prefix is represented as:
                (address1, address0, prefix_len)

        nexthop (tuple[int, int]):
            Next-hop IP address stored as a split 128-bit integer
            (address1, address0).

        origin (int | None):
            Raw ORIGIN attribute code:
                0 = IGP
                1 = EGP
                2 = INCOMPLETE
            None if the ORIGIN attribute is not present.

        as_path (list[int]):
            Flattened list of ASNs forming the AS_PATH attribute.

        as_path_segments (list[tuple[int, int, int]]):
            Metadata describing AS_PATH segments, preserving AS_SEQUENCE,
            AS_SET, and confederation boundaries.
            Each segment is represented as:
                (segment_type, segment_length, offset_into_as_path)

        communities (list[tuple[int, int, int, int]]):
            List of BGP community values stored in a future-proof,
            128-bit representation.
            Each community is represented as:
                (attr_type, value_len, high_64_bits, low_64_bits)

    Notes:
        - No protocol field is stored as a string internally.
        - String representations (IP addresses, prefixes, AS paths,
          communities) are generated lazily for debugging or display.
        - The representation is suitable for zero-copy transfer to
          NumPy, CuPy, or Arrow-based analytics pipelines.
    """

    def __init__(self, mrtentry):
        e = mrtentry.contents

        self._type = int(e.entryType)
        self._bgpType = int(e.bgpType)

        # timestamp (float seconds)
        self._ts = float(e.time) + (float(e.time_ms) / 1_000_000.0)

        self._peer_asn = int(e.peer_asn)
        self._peer_addr = (int(e.peer_address1), int(e.peer_address0))

        # origin
        self._origin_present = bool(int(e.origin_present))
        self._origin = int(e.origin) if self._origin_present else None

        # next hop
        self._nexthop = (int(e.nextHop_address1), int(e.nextHop_address0))

        # prefixes: store native, optionally also keep string view helpers
        self._withdraws = [
            (int(e.withdraw_address1[i]), int(e.withdraw_address0[i]), int(e.withdraw_prefix_len[i]))
            for i in range(int(e.nbWithdraw))
        ]
        self._nlri = [
            (int(e.nlri_address1[i]), int(e.nlri_address0[i]), int(e.nlri_prefix_len[i]))
            for i in range(int(e.nbNLRI))
        ]

        # AS-PATH: flattened ASNs + segment metadata
        self._as_path = [int(e.asPath[i]) for i in range(int(e.asPathLen))]
        self._as_path_segments = [
            (int(e.asPathSegType[s]),
            int(e.asPathSegLen[s]),
            int(e.asPathSegOffset[s]))
            for s in range(int(e.asPathSegCount))
        ]

        # Communities: future-proof 128-bit lanes + metadata
        self._communities = [
            (int(e.communities_attr_type[i]),
            int(e.communities_value_len[i]),
            int(e.communities1[i]),
            int(e.communities0[i]))
            for i in range(int(e.communities_count))
        ]

        # Setup msgType (same behavior as before)
        self._msgType = "Unknown"
        if self.type == BGP_TYPE_ZEBRA_BGP or self.type == BGP_TYPE_ZEBRA_BGP_ET:
            if self._bgpType == BGP_TYPE_OPEN:
                self._msgType = "O"
            elif self._bgpType == BGP_TYPE_UPDATE:
                self._msgType = "U"
            elif self._bgpType == BGP_TYPE_NOTIFICATION:
                self._msgType = "N"
            elif self._bgpType == BGP_TYPE_KEEPALIVE:
                self._msgType = "K"
            elif self._bgpType == BGP_TYPE_STATE_CHANGE:
                self._msgType = "S"
        elif self._type == BGP_TYPE_TABLE_DUMP_V2:
            self._msgType = "R"

    # --- properties (native forms) ---

    @property
    def ts(self) -> float:
        return self._ts

    @property
    def type(self) -> int:
        return self._type

    @property
    def nlri(self):
        # list[tuple[address1,address0,prefix_len]]
        return self._nlri

    @property
    def withdraws(self):
        return self._withdraws

    @property
    def origin(self):
        # int or None
        return self._origin

    @property
    def nexthop(self):
        # (addr1, addr0)
        return self._nexthop

    @property
    def as_path(self):
        # list[int]
        return self._as_path

    @property
    def as_path_segments(self):
        # list[{"type","len","off"}]
        return self._as_path_segments

    @property
    def communities(self):
        # list[{"attr_type","value_len","hi","lo"}]
        return self._communities

    @property
    def peer_asn(self) -> int:
        return self._peer_asn

    @property
    def peer_addr(self):
        # (addr1, addr0)
        return self._peer_addr

    @property
    def msgType(self) -> str:
        return self._msgType

    @property
    def bgpType(self) -> int:
        return self._bgpType

    # --- convenience string views (optional) ---

    @property
    def origin_str(self) -> str:
        return "" if self._origin is None else _decode_origin(self._origin)

    @property
    def peer_addr_str(self) -> str:
        a1, a0 = self._peer_addr
        return _u128_to_ip(a1, a0)

    @property
    def nexthop_str(self) -> str:
        a1, a0 = self._nexthop
        return _u128_to_ip(a1, a0)

    @property
    def nlri_str(self):
        return [_prefix_to_str(a1, a0, plen) for (a1, a0, plen) in self._nlri]

    @property
    def withdraws_str(self):
        return [_prefix_to_str(a1, a0, plen) for (a1, a0, plen) in self._withdraws]

    @property
    def as_path_str(self) -> str:
        return " ".join(str(x) for x in self._as_path)

    @property
    def communities_str(self) -> str:
        parts = []
        for (attr_type, value_len, hi, lo) in self._communities:
            if attr_type == 8 and value_len == 4 and hi == 0:
                parts.append(_classic_comm_to_str(lo & 0xFFFFFFFF))
            else:
                parts.append(f"{attr_type}:{value_len}:{hi:016x}{lo:016x}")
        return " ".join(parts)

    def __str__(self):
        # Keep the old pipe format for readability/debug,
        # but computed from native fields.
        return "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(
            self.msgType,
            self.ts,
            ",".join(self.nlri_str),
            ",".join(self.withdraws_str),
            self.origin_str,
            self.nexthop_str,
            self.as_path_str,
            self.communities_str,
            self.peer_asn,
            self.peer_addr_str,
        )
    



mylib = ctypes.CDLL("{}/libbgproutesmrt.so".format(BGPROUTESMRT_LIBRARY_PATH))

mylib.File_buf_create.argtypes = (ctypes.c_char_p,)
mylib.File_buf_create.restype  = ctypes.POINTER(FILE_BUF_T)

mylib.File_buf_close_dump.argtypes = (ctypes.POINTER(FILE_BUF_T),)
mylib.File_buf_close_dump.restype  = None

mylib.Read_next_mrt_entry.argtypes = (ctypes.POINTER(FILE_BUF_T),)
mylib.Read_next_mrt_entry.restype  = ctypes.POINTER(MRT_ENTRY)

mylib.MRTentry_free.argtypes = (ctypes.POINTER(MRT_ENTRY),)
mylib.MRTentry_free.restype  = None



def download_file(url :str, peer :str, timeout):
    """
    Download a BGP dump file from remote GILL's database and store it on local disk.

    Args:
        url (str): URL of the file that need to be donwloaded.
        peer (str): BGP peer from which the downloaded data has been collected
        timeout (int): Number of seconds after which the URL request will be timed out.

    Returns:
        str: The name of the file on which the collected data has been stored on the local
        disk. Returns 'None' in case Exception occured during the downloading.
    """

    ts = url.split("/")[-1].replace(".mrt.bz2", "")
    try:
        response = requests.get(url, stream=True, timeout=timeout)

        if response.status_code != 200:
            return None

        if not os.path.exists("/tmp/bgproutesmrt"):
            os.mkdir("/tmp/bgproutesmrt")

        fn = "/tmp/bgproutesmrt/{}_{}.mrt.bz2".format(peer, ts)

        with open(fn, "wb") as f:
            for chunk in response.iter_content(chunk_size=4096):  # 1KB chunks
                if chunk:
                    f.write(chunk)
        
        return fn

    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return None
    except ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
        return None
    except Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
        return None
    except Exception as err:
        print(f"An error occurred: {err}")
        return None



def query_broker(url, timeout):
    """
    Perform a query to the remote GILL file broker.

    Args:
        url (str): URL of the query performed. The URL must contain the required
        endpoint, as well as the correct parameters.
        timeout (int): Number of seconds after which the URL request will be timed out.

    Returns:
        json: Returns a JSON dataframe where each key corresponds to the BGP peer from which 
        we will get the data, and the associated value is the list of files that needs to be
        process for this BGP peer, according to the parameters of the broker request. Returns
        None in case anything wrong happen.
    """

    try:
        response = requests.get(url, stream=True, timeout=timeout)

        if response.status_code != 200:
            return None

        return json.loads(response.content.decode())

    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return None
    except ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
        return None
    except Timeout as timeout_err:
        return None
    except Exception as err:
        print(f"An error occurred: {err}")
        return None



def parse_one_file(fn :str):
    """
    Parse a single MRT file and yields every single MRT entry.

    Args:
        fn (str): Name of the file that must be processed. The file can be either compressed 
        or uncompressed.

    Yields:
        BGPmessage: Yields every single MRT entry by transforming them into a BGP message.

    Returns:
        int: return 0 if evrything went well, -1 otherwise.
    """

    dumper = mylib.File_buf_create(fn.encode())

    if not dumper:
        return -1

    while dumper.contents.eof == 0:
        entry = mylib.Read_next_mrt_entry(dumper)

        if entry:
            if entry.contents.entryType == BGP_TYPE_ZEBRA_BGP or entry.contents.entryType == BGP_TYPE_ZEBRA_BGP_ET:
                msg = BGPmessage(entry)
                yield msg
            elif entry.contents.entryType == BGP_TYPE_TABLE_DUMP_V2 and \
                (entry.contents.entrySubType == BGP_SUBTYPE_RIB_IPV4_UNICAST or entry.contents.entrySubType == BGP_SUBTYPE_RIB_IPV6_UNICAST):
                msg = BGPmessage(entry)
                yield msg

            #mylib.MRTentry_free(entry)
        
    mylib.File_buf_close_dump(dumper)

    return 0



def date_to_gmt_timestamp(date_str :str):
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
    dt = dt.replace(tzinfo=datetime.timezone.utc)  # ensure UTC
    timestamp = int(dt.timestamp())

    return timestamp


class BGProutesMRT:
    """
    Structure representing a Stream of GILL messages.

    Attributes:
        from_time (str, int, float): Time from which we should start getting the data. In case
        this parameter is a string, must be of the form of 'YYYY-MM-DD HH:MM:SS'. Otherwise,
        must be a UNIX timestamp.

        until_time (str, int, float): Time from which we should start getting the data. In case
        this parameter is a string, must be of the form of 'YYYY-MM-DD HH:MM:SS'. Otherwise,
        must be a UNIX timestamp.

        record_type (str): Specify which type of data must be downloaded. For now, only 'updates'
        and 'ribs' are supported.

        vps (list): Represent the list of Vantage Points from which we want to collect the data.
        Each VP must be of the form 'ASN_IP'. In case this parameter is not set, collect data from
        all VPs.

        all_files (list): List of all files that need to be downloaded to process all required data.
        remaining_files (list): List of files that e still need to process.
        dumper (FILE_BUF_T): Structure of the file dumper.
    """

    def __init__(self, from_time, until_time, record_type :str, peering_protocol='bgp', vps=None):
        """
        Initialize the Stream of GILL data. Query the broker to know precisely which files
        need to be downloaded and processed.

        Args:
            from_time (str, int, float): Time from which we should start getting the data. In case
            this parameter is a string, must be of the form of 'YYYY-MM-DD HH:MM:SS'. Otherwise,
            must be a UNIX timestamp.

            until_time (str, int, float): Time from which we should start getting the data. In case
            this parameter is a string, must be of the form of 'YYYY-MM-DD HH:MM:SS'. Otherwise,
            must be a UNIX timestamp.

            record_type (str): Specify which type of data must be downloaded. For now, only 'updates'
            and 'ribs' are supported.

            peering_protocol (str): Tell from which peering protocol we should get the data (either
            'bgp' or 'bmp').

            vps (list): Represent the list of Vantage Points from which we want to collect the data.
            Each VP must be of the form 'ASN_IP'. In the case of BMP (i.e., when we set peering_protocol='bmp'),
            each VP must be of the form 'ASN_IP|parent_ASN_perantIP'. In case this parameter is not set, 
            collect data from all VPs corresponding to the set peering protocol. 
        """
        
        self.from_time = 0
        self.until_time = 0

        self.vps = vps
        self.record_type = record_type
        self.peering_protocol = peering_protocol

        self.all_files = list()
        self.remaining_files = list()
        self.dumper = None

        self.actFile = None

        if isinstance(from_time, int):
            self.from_time = from_time
        elif isinstance(from_time, float):
            self.from_time = int(from_time)
        elif isinstance(from_time, str):
            try:
                self.from_time = date_to_gmt_timestamp(from_time)
            except:
                print("Date must be on the format 'YYYY-MM-DDTHH:MM:SS'")
                exit(1)

        if isinstance(until_time, int):
            self.until_time = until_time
        elif isinstance(until_time, float):
            self.until_time = int(until_time)
        elif isinstance(until_time, str):
            try:
                self.until_time = date_to_gmt_timestamp(until_time)
            except:
                print("Date must be on the format 'YYYY-MM-DDTHH:MM:SS'")
                exit(1)

        if self.vps:
            http_request = "https://mrt-broker.bgproutes.io/broker?peering_protocol={}&vps={}&from_time={}&until_time={}&data_type={}".format(self.peering_protocol, ",".join(self.vps), self.from_time, self.until_time, self.record_type)
        else:
            http_request = "https://mrt-broker.bgproutes.io/broker?peering_protocol={}&from_time={}&until_time={}&data_type={}".format(self.peering_protocol, self.from_time, self.until_time, self.record_type)


        timeout = 1
        data = None

        while data is None and timeout < 128:
            data = query_broker(http_request, timeout)
            timeout *= 2

        if not data:
            print("Unable to join broker, please report the error to 'contact@bgproutes.io'. Error on querying endpoint '{}'.".format(http_request))
            exit(1)

        if "error" in data:
            print("Error from broker: '{}'".format(data["error"]))

        
        for peer in data["files"]:
            for fn in data["files"][peer]:
                self.all_files.append((fn, peer))
                self.remaining_files.append((fn, peer))

        self.all_files = sorted(self.all_files)
        self.remaining_files = sorted(self.remaining_files)

    

    def download_and_open_next_dumper(self):
        """
        Function that close the latest BGP dumper (if any), download the file that must be 
        processed next, and open the corresponding MRT file dumper.
        """

        if self.dumper:
            mylib.File_buf_close_dump(self.dumper)
            self.dumper = None

        if self.actFile:
            os.remove(self.actFile)

        if not len(self.remaining_files):
            return 0
        
        (url, peer) = self.remaining_files.pop(0)

        timeout = 1
        fn = download_file(url, peer, timeout)

        while not fn and timeout < 64:
            timeout *= 2
            fn = download_file(url, peer, timeout)
        
        if not fn:
            print("Skip file {}, unable to download".format(url))
            return 2
        
        self.dumper = mylib.File_buf_create(fn.encode())
        self.actFile = fn

        return 1
    

    def get_all_data(self):
        """
        Function used to get all the data required to process the query. While there
        are some files to be processed, download the new one and yield every BGP message
        contained in the MRT file.

        Yields:
            BGPmessage: Yields every BGP message found in each files reuired to perform the
            query correctly.
        """

        while len(self.remaining_files):
            if not self.dumper or self.dumper.contents.eof != 0:
                ret = self.download_and_open_next_dumper()

                if ret == 0:
                    return
                
                while ret == 2:
                    ret = self.download_and_open_next_dumper()
                    if ret == 0:
                        return
            

            while self.dumper.contents.eof == 0:
                entry = mylib.Read_next_mrt_entry(self.dumper)

                if entry and entry.contents.time >= self.from_time and entry.contents.time <= self.until_time:

                    # If entry is a MRT BGP UPDATE, print it
                    if entry.contents.entryType == BGP_TYPE_ZEBRA_BGP or entry.contents.entryType == BGP_TYPE_ZEBRA_BGP_ET:
                        msg = BGPmessage(entry)
                        yield msg

                    # If entry is a RIB entry, print it as well
                    elif entry.contents.entryType == BGP_TYPE_TABLE_DUMP_V2 and \
                        (entry.contents.entrySubType == BGP_SUBTYPE_RIB_IPV4_UNICAST or entry.contents.entrySubType == BGP_SUBTYPE_RIB_IPV6_UNICAST):
                        msg = BGPmessage(entry)
                        yield msg

                    #mylib.MRTentry_free(entry)

        if self.dumper:
            mylib.File_buf_close_dump(self.dumper)
            self.dumper = None

        if self.actFile:
            os.remove(self.actFile)



