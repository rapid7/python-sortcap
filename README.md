python-sortcap
==============

Or in short: sortcap

## Problem Statement

Medium to large sized PCAPs are tricky to "access" in the sense that all tools will go over the whole file to show details about a certain connection / ip.

## Sortcap

We just sort the pcap's packets, ordered by the "connection tuple" (src, sport, dst, dport, proto). This way you can remember the offset of the first packet for one of the tuples, and then efficiently extract all related packets. The connection information can then be indexed somehow so one can search for an ip / port to get the respective offsets.

## Example

```sh
./sortcap <input_pcap> <output_pcap>
```

Or with the Docker image:

```sh
docker run --rm --net=none -v $PWD:/pcap r7labs/sortcap /pcap/input.pcap /pcap/output.pcap
```

If you have a pcapng or pcapng.gz etc, you need to preprocess with mergecap

```sh
docker run --rm --net=none -v $PWD:/pcap --entrypoint mergecap r7labs/sortcap -F pcap -w /pcap/output.pcap /pcap/input.pcapng.gz
```

## Future work

 * Support pcapng / gzipped natively
 * Other indexing options (see --index)
 * Other protocol types?
