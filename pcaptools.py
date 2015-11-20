
import os
import dpkt
import socket

import sqlite3
import heapq
from tempfile import gettempdir
from itertools import islice
from collections import namedtuple

TMPD = gettempdir()
Keyed = namedtuple("Keyed", ["key", "obj"])
Packet = namedtuple("Packet", ["raw", "ts"])

def index_pcap(path):
    sqlite_path = os.path.splitext(path)[0] + ".index.sqlite"
    db = sqlite3.connect(sqlite_path)
    c = db.cursor()
    c.execute('create table if not exists streams (id integer primary key, src text, sport integer, dst text, dport integer, proto text, offset integer)')
    c.close()
    db.commit()

    c = db.cursor()
    for src, dst, sport, dport, proto, offset in pcap_flowtuples(path):
        c.execute("insert into streams (src, sport, dst, dport, proto, offset) values (?,?,?,?,?,?)", (src, sport, dst, dport, proto, offset))

    c.close()
    db.commit()
    c = db.cursor()
    c.execute('create index if not exists srcindex on streams (src)')
    c.execute('create index if not exists dstindex on streams (dst)')
    c.execute('create index if not exists sportindex on streams (sport)')
    c.execute('create index if not exists dportindex on streams (dport)')
    c.close()
    db.commit()
    db.close()

def pcap_flowtuples(path):
    fd = open(path, "rb")
    pcap = dpkt.pcap.Reader(fd)
    linktype = pcap.datalink()

    offset = fd.tell()
    prev = None

    for ts, buf in pcap:
        sip, dip, sport, dport, proto = flowtuple_from_raw(buf, linktype)

        if prev != (sip, dip, sport, dport, proto) and prev != (dip, sip, dport, sport, proto):
            prev = (sip, dip, sport, dport, proto)
            yield sip, dip, sport, dport, proto, offset

        offset = fd.tell()

    fd.close()

def iplayer_from_raw(raw, linktype=1):
    """Converts a raw packet to a dpkt packet regarding of link type.
    @param raw: raw packet
    @param linktype: integer describing link type as expected by dpkt
    """
    if linktype == 1: # ethernet
        pkt = dpkt.ethernet.Ethernet(raw)
        ip = pkt.data
    elif linktype == 101: # raw
        ip = dpkt.ip.IP(raw)
    else:
        raise Exception("unknown PCAP linktype")
    return ip

def flowtuple_from_raw(raw, linktype=1):
    """Parse a packet from a pcap just enough to gain a flow description tuple"""
    ip = iplayer_from_raw(raw, linktype)

    if isinstance(ip, dpkt.ip.IP):
        sip, dip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        proto = ip.p

        if proto == dpkt.ip.IP_PROTO_TCP or proto == dpkt.ip.IP_PROTO_UDP:
            l3 = ip.data
            sport, dport = l3.sport, l3.dport
        else:
            sport, dport = 0, 0

    else:
        sip, dip, proto = 0, 0, -1
        sport, dport = 0, 0

    flowtuple = (sip, dip, sport, dport, proto)
    return flowtuple

def payload_from_raw(raw, linktype=1):
    """Get the payload from a packet, the data below TCP/UDP basically"""
    ip = iplayer_from_raw(raw, linktype)
    try: return ip.data.data
    except:
        return ""

def next_connection_packets(piter, linktype=1):
    """Extract all packets belonging to the same flow from a pcap packet iterator"""
    first_ft = None

    for ts, raw in piter:
        ft = flowtuple_from_raw(raw, linktype)
        if not first_ft: first_ft = ft

        sip, dip, sport, dport, proto = ft
        if not (first_ft == ft or first_ft == (dip, sip, dport, sport, proto)):
            break

        yield {
            "src": sip, "dst": dip, "sport": sport, "dport": dport, "proto": proto,
            "raw": payload_from_raw(raw, linktype).encode("base64"), "direction": first_ft == ft,
        }

def packets_for_stream(fobj, offset):
    """Open a PCAP, seek to a packet offset, then get all packets belonging to the same connection"""
    pcap = dpkt.pcap.Reader(fobj)
    pcapiter = iter(pcap)
    ts, raw = pcapiter.next()

    fobj.seek(offset)
    for p in next_connection_packets(pcapiter, linktype=pcap.datalink()):
        yield p


# input_iterator should be a class that als supports writing so we can use it for the temp files
# this code is mostly taken from some SO post, can't remember the url though
def batch_sort(input_iterator, output_path, buffer_size=1024**2, output_class=None):
    """batch sort helper with temporary files, supports sorting large stuff"""
    if not output_class:
        output_class = input_iterator.__class__

    chunks = []
    try:
        while True:
            current_chunk = list(islice(input_iterator,buffer_size))
            if not current_chunk:
                break
            current_chunk.sort()
            output_chunk = output_class(os.path.join(TMPD, "%06i" % len(chunks)))
            chunks.append(output_chunk)

            for elem in current_chunk:
                output_chunk.write(elem.obj)
            output_chunk.close()

        output_file = output_class(output_path)
        for elem in heapq.merge(*chunks):
            output_file.write(elem.obj)
        output_file.close()
    except:
        raise
    finally:
        for chunk in chunks:
            try:
                chunk.close()
                os.remove(chunk.name)
            except Exception:
                pass

# magic
class SortCap(object):
    """SortCap is a wrapper around the packet lib (dpkt) that allows us to sort pcaps
    together with the batch_sort function above."""

    def __init__(self, path, linktype=1):
        self.name = path
        self.linktype = linktype
        self.fd = None
        self.ctr = 0 # counter to pass through packets without flow info (non-IP)
        self.conns = set()

    def write(self, p):
        if not self.fd:
            self.fd = dpkt.pcap.Writer(open(self.name, "wb"), linktype=self.linktype)
        self.fd.writepkt(p.raw, p.ts)

    def __iter__(self):
        if not self.fd:
            self.fd = dpkt.pcap.Reader(open(self.name, "rb"))
            self.fditer = iter(self.fd)
            self.linktype = self.fd.datalink()
        return self

    def close(self):
        self.fd.close()
        self.fd = None

    def next(self):
        rp = next(self.fditer)
        if rp is None: return None
        self.ctr += 1

        ts, raw = rp
        rpkt = Packet(raw, ts)

        sip, dip, sport, dport, proto = flowtuple_from_raw(raw, self.linktype)

        # check other direction of same flow
        if (dip, sip, dport, sport, proto) in self.conns:
            flowtuple = (dip, sip, dport, sport, proto)
        else:
            flowtuple = (sip, dip, sport, dport, proto)

        self.conns.add(flowtuple)
        return Keyed((flowtuple, ts, self.ctr), rpkt)

def sort_pcap(inpath, outpath):
    """Use SortCap class together with batch_sort to sort a pcap"""
    inc = SortCap(inpath)
    batch_sort(inc, outpath, output_class=lambda path: SortCap(path, linktype=inc.linktype))
    return 0
