# Malicious Access Point Detective (MalAP Detective) - Server Side

## 1. Introduction

​	Our project in detecting malicious AP(Access Point) includes two parts: ARP spoofing detection and DNS spoofing detection. The system architecture is **C-S model**, with `distributed` servers(Root server and branch servers). This version of server follows the application layer protocol: `VeriDNS protocol` defined by ourselves, to ensure the communication between serverside and clientside, using `secured socket layer` protocol. 

​	Potential DNS spoofed records' verification follows the process below: 

- Listen on port 4433 which is self-defined by `VeriDNS protocol`, and receiving packets from client. 
  - One typical packet has its type either `Branch-Server Request` or `VeriDNS request`. 
- If request type = `Branch-Server Request`
  - Check the client's country
  - Return the branch server's **IPv4 address** which is nearest to the client.
  - Default return is the IPv4 address of the root server itself.
 - If request type = `VeriDNS Request`
   - Collect the **Open IP lists** maintained by trusted entities. All the lists collected are **deduplicated and integrated**. 
   - Call considerable amount of **authorized DNS request APIs** to query the domain name, collecting the results in another list, with **deduplication and integration**.
   - Use **regex** to compare the records. If there're records from the client that are not in the lists generated as above, then return the malicious IPs as a list to the client.

​	This is the server side code. To run this application on your own deployed server, follow the instructions below.

## 2. Runtime Environment

#### **Runtime Environment:**

```
Python>=3.1.0
requests~=2.28.2
geoip2~=4.7.0
```

#### **Other Information**:

​	**To start the server:**

- Make sure you have allowed the application to **access the network through port 4433**. (can be changed)
- Make sure you have successfully **installed the `geoip database`** and store it to **current runtime directory.** 
  - To install the geoip database, access https://www.maxmind.com/en/accounts/current/geoip/downloads. Create your own account, then download `GeoLite2-City.mmdb`.

## 3. Appendix - VeriDNS Protocol

### VeriDNS Protocol

Default listening  port #: 4433 (for the machine who act as the server in communication)

Note that the field name is **case sensitive** and the order of the fields is **sensitive**.

#### 1 Header

Asterisk (*) indicates the field is required for **all packets** in **all types**.

| Field Name        | Data Type    | Length  | Description                                                  |
| ----------------- | ------------ | ------- | ------------------------------------------------------------ |
| `Type`*           | unsigned int | 4 bytes | 0: Branch Server Address Query. The client sends such kind of message to the VeriDNS root server to query the IP addresses of VeriDNS branch servers. The branch servers should be located in the same country or region as the client.<br />1: Branch Server Address Answer. The VeriDNS root server answers the client with the VeriDNS branch server IP address.<br />2: VeriDNS request. The client ask the VeriDNS branch server to validate the given IP addresses. <br />3: VeriDNS response. The VeriDNS branch server tells the client whether the given DNS response is malicious or not. |
| `Length`*         | unsigned int | 4 bytes | header.length + body.length. The unit is **byte**            |
| `SequenceNumber`* | unsigned int | 4 bytes | identifier of the packet.<br />The sequence number of the first packet (i.e. initial sequence number, ISN) in a session should be selected randomly.<br />After the old session is closed and a new one is initiated, a new ISN should be selected randomly again. **Note that the session between the client and the root server is different from that between the client and branch servers.** Therefore, a new ISN should be used between the client and branch servers after the query session between the client and the root server terminates.<br />Servers should response the query / request with the same sequence number which presents in the corresponding query / request.<br />In an active session, sequence number will increase by 1 if a new request / query is sent to the server. |

#### 2 Body

##### 2.1 Branch Server Address Query

No packet body

##### 2.2 Branch Server Address Answer

All fields are required for such type of packets.

| Field Name     | Data Type              | Length       | Description                                                  |
| -------------- | ---------------------- | ------------ | ------------------------------------------------------------ |
| `NumberOfAddr` | unsigned int           | 4 bytes      | length of  `BranchIPAddress`  array (i.e. number of IP addresses stored in the array) |
| `BranchIPAddr` | unsigned int **array** | **variable** | IPv4 address(es) for the branch VeriDNS server. The order is **sensitive**. The client will try them from the first to the last. |

##### 2.3 VeriDNS request

All fields are required for such type of packets.

| Field Name     | Data Type              | Length       | Description                                                  |
| -------------- | ---------------------- | ------------ | ------------------------------------------------------------ |
| `DomainName`   | UTF-8 string           | 256 bytes    | The domain name to be translated. If the string length is less than 256 bytes, the remaining bytes should be set to `0x00`. |
| `NumberOfAddr` | unsigned int           | 4 bytes      | length of  `IPAddress`  array (i.e. number of IP addresses stored in the array) |
| `IPAddress`    | unsigned int **array** | **variable** | An array which stores IPv4 address(es) for the `DomainName` captured from DNS responses on the client machine. |

##### 2.4 VeriDNS response

Asterisk (*) indicates the field is required.

| Field Name      | Data Type              | Length       | Description                                                  |
| --------------- | ---------------------- | ------------ | ------------------------------------------------------------ |
| `Verification`* | boolean                | 1 byte       | The verification result for the `IPAddress`<br />0: false, which means at least one IP address in the `IPAddress` array has problem.<br />1: true, which means all IP addresses are verified. |
| `NumberOfAddr`  | unsigned int           | 4 bytes      | If `Verification == 0`, this field is required. Otherwise, it may be ignored by the client. It indicates the length of `MaliciousIP` array. (i.e. number of elements stored in the array) |
| `MaliciousIP`   | unsigned int **array** | **variable** | If `Verification == 0`, this field is required. Otherwise, it may be ignored by the client. If an IP address in the `IPAddress` array seems to be malicious, it will put into `MaliciousIP` array. |

#### 3 Sample of the Packets

##### 3.1 Branch Server Address Query

- In hex form:

| Type        | Length      | SequenceNumber |
| ----------- | ----------- | -------------- |
| 00 00 00 00 | 00 00 00 0C | 00 13 31 CF    |

- In human readable form:

| Type | Length | SequenceNumber |
| ---- | ------ | -------------- |
| 0    | 12     | 1257935        |

##### 3.2 Branch Server Address Answer

- In hex form:

| Type        | Length      | SequenceNumber | NumberOfAddr | BranchIPAddr            |
| ----------- | ----------- | -------------- | ------------ | ----------------------- |
| 00 00 00 01 | 00 00 00 18 | 00 13 31 CF    | 00 00 00 02  | 01 01 01 01 08 08 08 08 |

- In human readable form:

| Type | Length | SequenceNumber | NumberOfAddr | BranchIPAddr     |
| ---- | ------ | -------------- | ------------ | ---------------- |
| 1    | 24     | 1257935        | 2            | 1.1.1.1, 8.8.8.8 |

##### 3.3 VeriDNS request

- In hex form:

| Type        | Length      | SequenceNumber | DomainName                                                   | NumberOfAddr | IPAddress               |
| ----------- | ----------- | -------------- | ------------------------------------------------------------ | ------------ | ----------------------- |
| 00 00 00 02 | 00 00 01 18 | 03 4A A9 2D    | 77 77 77 2E 67 69 74 68 75 62 2E 63 6F 6D 0A 00 00 00 ... 00 00 00 | 00 00 00 02  | 14 CD F3 A5 14 CD F3 A6 |

- In human readable form:

| Type | Length | SequenceNumber | DomainName     | NumberOfAddr | IPAddress                      |
| ---- | ------ | -------------- | -------------- | ------------ | ------------------------------ |
| 2    | 280    | 55224621       | www.github.com | 2            | 20.205.243.165, 20.205.243.166 |

##### 3.4 VeriDNS response

- In hex form:

| Type        | Length      | SequenceNumber | Verification | NumberOfAddr | MaliciousIP |
| ----------- | ----------- | -------------- | ------------ | ------------ | ----------- |
| 00 00 00 03 | 00 00 00 15 | 03 4A A9 2D    | 00           | 00 00 00 01  | 14 CD F3 A5 |

- In human readable form:

| Type | Length | SequenceNumber | Verification | NumberOfAddr | MaliciousIP    |
| ---- | ------ | -------------- | ------------ | ------------ | -------------- |
| 3    | 21     | 55224621       | 0            | 1            | 20.205.243.165 |

