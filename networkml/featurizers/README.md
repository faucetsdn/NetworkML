# Host-Related Features in NetworkML Models

Machine learning models require inputs (or "features" in the language of machine learning practitioners.) NetworkML, a machine learning model that operates on network traffic, is no different. This readme describes the features that networkML can create and can therefore be included in NetworkML's models. All features can either be created for each host present, which therefore creates a numeric representation of all the traffic flowing into and out of a host, or for each session, which describes a particular data exchange for two hosts defined by a 5-tuple of source and destination IP's, source and destination ports, and protocol. This readme focuses on the host-related features. These features were devised with enterprise networks as the likely site of NetworkML deployment. Additionally, these features have a focus on both IP and non-IP traffic at layer 2, which is different than many other network traffic analysis models.

A key at the bottom of this page explains the symbols associated with each feature set.

## IP Protocol-Specific Features

IPv4 (b)

IPv6 (b)

Well-known Ethernet protocols (b) [Note: Each flag is assigned an individual boolean vector. See list of ethernet protocols at the bottom of the page.]

TCP ports (i/o) \(P\) (P/NP) (b)

UDP ports (i/o) (P/NP) (b)

TCP flags (i/o) (b) [Note: Each flag is assigned an individual boolean vector.]

IP flags (i/o) (b)

IPX (b)

Both private IP (b)

IPv4 multicast (b)

IP differentiated services (i/o) (b)

Well-known IP protocols (b) [Note: Each protocol is assigned an individual boolean vector. See list of IP protocols at the bottom of the page.]

## Non-IP Features

VLAN ID (b)

Non-IP protocol (b)

## Packet Timing-related Features
Interarrival time (D) (S) \(r\)

## Packet Size-related Features
Frame length (D) (S) \(r\)

## Feature Key
**Directionality**
Indicates that there are versions of a feature for different traffic directions

(i) = incoming packets

(o) = outgoing packets

(bi) = bidirectional flow

(D) = i + o + bi

**Statistics**
Indicates that there are versions of a feature for each statistic

(S) Statistics = (min, 25th percentile, median, 75th percentile, max, mean, variance, count, sum)

**Well Known Ports**
Indicates that features are port-specific

\(P\) Private ports = (22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 137, 138, 139, 143, 161, 443, 631, other)

(NP) Non-private ports = (1900, 2375, 5222, 5349, 5353, 5354, 5349, 5357, 6653, other)

**Type of values**
Indicates the acceptable values for a feature

(b) = binary feature (0, 1)

\(r\) = real number feature (-inf, +inf)

Example: Frame length (D) (S) \(r\) indicates that there are versions of this feature for incoming packets, outgoing packets, and bidirectional flows and also sub-versions for each different statistic. In total, there are 27 features.

Ethernet protocols: Well-known ethernet protocols include ethernet, IPv6, IP, TCP, ARP, ICMP, GRE, ESP.
IP protocols: Well-known IP protocols include TCP, UDP, ICMP, ICMPv6, ARP, and an other category.
