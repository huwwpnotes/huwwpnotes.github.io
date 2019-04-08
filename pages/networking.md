---
layout: page
title: Networking
permalink: /networking/
---

# Index

* [tcp/ip](#tcp/ip)
* [DNS](#dns)
* [NAT](#nat)
* [DHCP](#dhcp)
* [NetBIOS](#netbnios)
* [SNMP](#snmp)

## TCP/IP

TCP/IP, or the Transmission Control Protocol/Internet Protocol, is a suite of communication protocols used to interconnect network devices on the internet.

TCP/IP specifies how data is exchanged over the internet by providing end-to-end communications that identify how it should be broken into packets, addressed, transmitted, routed and received at the destination.

### Application Layer

The application layer is the scope within which applications, or processes, create user data and communicate this data to other applications on another or the same host. All the high level protocols (HTTP, FTP, SSH, etc) operate within the application layer and make use of the lower layers in transmitting data.

### Transport Layer

The transport layer performs host-to-host communications on either the same or different hosts and on either the local network or remote networks separated by routers. It provides a channel for the communication needs of applications. UDP and TCP are the two protocols used in the transport layer. 

### Network Layer

The internet layer exchanges datagrams across network boundaries. It provides a uniform networking interface that hides the actual topology (layout) of the underlying network connections. The primary protocol in this scope is the Internet Protocol, which defines IP addresses. Its function in routing is to transport datagrams to the next IP router that has the connectivity to a network closer to the final data destination. ICMP also operates on this layer.

### Physical Layer

The physical layer defines the networking methods within the scope of the local network link on which hosts communicate without intervening routers. This layer includes the protocols used to describe the local network topology and the interfaces needed to effect transmission of Internet layer datagrams to next-neighbor hosts.

## DNS

The Domain Name System resolves the names of internet sites with their underlying IP addresses.

1. Your computer sends a DNS Query to the recursive resolver. This is a server usually provided by your ISP or optionally a third party.
2. The resolver handles the querying from here on out. First it queries the root servers (one of 13 IP addresses with many fallback servers) for the address of the Top Level Domain namerservers (.com, .net, etc).
3. The recursive resolver then queries the TLD namerserver for the address of the domain nameserver (*example*.com)
4. The resursive resolve then queries the domain server which returns the IP address of the full domain *example.com*
5. The recursive resolver then returns the IP address to the client, completing the DNS query

### CNANME Records

Usually DNS queries return A Records (a for address) which is the IP address for the queried name.

The ‘canonical name’ record is used in lieu of an A record, when a domain or subdomain is an alias of another domain.

Oftentimes, when sites have subdomains such as blog.example.com or shop.example.com, those subdomains will have CNAME records which point to a root domain (example.com). This way if the IP of the host changes, only the DNS A record for the root domain needs to be updated and all the CNAME records will follow along with whatever changes are made to the root.

A frequent misconception is that a CNAME record must always resolve to the same website as the domain it points to, but this is not the case. The CNAME record only points the client to the same IP address as the root domain. Once the client hits that IP address, the web server will still handle the URL accordingly. So for instance, blog.example.com might have a CNAME that points to example.com, directing the client to example.com’s IP address. But when the client actually connects to that IP address, the web server will look at the URL, see that it’s blog.example.com, and deliver the blog page rather than the home page.

### DNS reflection attacks

DNS reflection attacks can swamp victims with high-volume messages from DNS resolver servers. Attackers request large DNS files from all the open DNS resolvers they can find and do so using the spoofed IP address of the victim. When the resolvers respond, the victim receives a flood of unrequested DNS data that overwhelms their machines.

### DNS cache poisoning

DNS cache poisoning can divert users to malicious Web sites. Attackers manage to insert false address records into the DNS so when a potential victim requests an address resolution for one of the poisoned sites, the DNS responds with the IP address for a different site, one controlled by the attacker.

## NAT

Network Address Translationis a method of remapping one IP address space into another by modifying network address information in the IP header of packets while they are in transit across a traffic routing device.[1] The technique was originally used as a shortcut to avoid the need to readdress every host when a network was moved. It has become a popular and essential tool in conserving global address space in the face of IPv4 address exhaustion. One Internet-routable IP address of a NAT gateway can be used for an entire private network.

## DHCP

The Dynamic Host Configuration Protocol (DHCP) is a network management protocol used on UDP/IP networks whereby a DHCP server dynamically assigns an IP address and other network configuration parameters to each device on a network so they can communicate with other IP networks. A DHCP server enables computers to request IP addresses and networking parameters automatically from the Internet service provider (ISP), reducing the need for a network administrator or a user to manually assign IP addresses to all network devices. In the absence of a DHCP server, a computer or other device on the network needs to be manually assigned an IP address, or to assign itself an APIPA address, which will not enable it to communicate outside its local subnet.

DHCP can be implemented on networks ranging in size from home networks to large campus networks and regional Internet service provider networks. A router or a residential gateway can be enabled to act as a DHCP server. Most residential network routers receive a globally unique IP address within the ISP network. Within a local network, a DHCP server assigns a local IP address to each device connected to the network.

## NetBIOS

NetBIOS (Network Basic Input/Output System) is a program that allows applications on different computers to communicate within a local area network. Basically it allows software to communicate via netbios names. It can be carried over TCP/UDP. Often used in SMB. Can provide enumeration, check system notes.

## SNMP

Simple Network Management Protocol (SNMP) is an application-layer protocol used to manage and monitor network devices and their functions. SNMP provides a common language for network devices to relay management information within single- and multivendor environments in a local area network. Can be enumerated on using common 'community strings' for information.
