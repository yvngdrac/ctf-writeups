# DEEP PACKET ANALYSIS

**Author:** yvngdrac

**Date:** November 2025  
**Category:** Network Forensics  
**Difficulty:** Easy/Medium  
**Tools:** tshark, awk, xxd, base64

## Challenge Description
So i got this packet capture file that im supposed to analyze deeper not just on the surface level. The challenge name "Deep Packet Inspection" was a pretty big hint that i need to look beyond it which is a packet capture file containing DNS traffic with hidden data exfiltrated via DNS tunneling.

## Solution

### Step 1: Download and Extract
First thing first i need to download the challenge file.
```bash
wget 'https://barqsec.exploit3rs.ae/files/7339bce8a8b6cf311b86864814378108/challenge.zip' -O challenge.zip
unzip challenge.zip
```

### Step 2: Initial Analysis
I started with basics which i asked my buddy Deepseek that suggested to analyze the protocol hierarchy.

Protocol hierarchy:
```bash
tshark -r challenge.pcap -q -z io,phs
```
Output:
```bash
===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:376 bytes:35296
  arp                                    frames:20 bytes:840
  ip                                     frames:356 bytes:34456
    udp                                  frames:96 bytes:8492
      dns                                frames:96 bytes:8492
    tcp                                  frames:216 bytes:21620
      http                               frames:32 bytes:7812
    icmp                                 frames:44 bytes:4344
===================================================================

```
Next, i looked for DNS queries since it is a common spot for hiding data.

DNS queries analysis:
```bash
tshark -r challenge.pcap -Y "dns" -T fields -e dns.qry.name | head -20
```
Output:
```bash
www.google.com
www.google.com
api.github.com
api.github.com
www.cloudflare.com
www.cloudflare.com
stackoverflow.com
stackoverflow.com
www.reddit.com
www.reddit.com
cdn.jsdelivr.net
cdn.jsdelivr.net
fonts.googleapis.com
fonts.googleapis.com
ajax.googleapis.com
ajax.googleapis.com
www.facebook.com
www.facebook.com
www.twitter.com
www.twitter.com
www.amazon.com
www.amazon.com
x091337ff-00-04-525868776247397064444e7963337445.telemetry.microsoft-cloud.com
x091337ff-00-04-525868776247397064444e7963337445.telemetry.microsoft-cloud.com
x091337ff-01-04-4d7a4e77583141305932737a64463878.updates.cloudflare-cdn.com
x091337ff-01-04-4d7a4e77583141305932737a64463878.updates.cloudflare-cdn.com
x091337ff-02-04-626e4e774d324e304d54427558303030.telemetry.microsoft-cloud.com
x091337ff-02-04-626e4e774d324e304d54427558303030.telemetry.microsoft-cloud.com
x091337ff-03-04-6333517a636c38794d44493066513d3d.metrics.aws-cloudfront.net
x091337ff-03-04-6333517a636c38794d44493066513d3d.metrics.aws-cloudfront.net
www.google.com
www.google.com
api.github.com
api.github.com
www.cloudflare.com
www.cloudflare.com
stackoverflow.com
stackoverflow.com
www.reddit.com
www.reddit.com
cdn.jsdelivr.net
cdn.jsdelivr.net
fonts.googleapis.com
fonts.googleapis.com
ajax.googleapis.com
ajax.googleapis.com
www.facebook.com
www.facebook.com
www.twitter.com
www.twitter.com
www.amazon.com
www.amazon.com
www.google.com
www.google.com
api.github.com
api.github.com
www.cloudflare.com
www.cloudflare.com
stackoverflow.com
stackoverflow.com
www.reddit.com
www.reddit.com
cdn.jsdelivr.net
cdn.jsdelivr.net
fonts.googleapis.com
fonts.googleapis.com
ajax.googleapis.com
ajax.googleapis.com
www.facebook.com
www.facebook.com
www.twitter.com
www.twitter.com
www.amazon.com
www.amazon.com
www.google.com
www.google.com
api.github.com
api.github.com
www.cloudflare.com
www.cloudflare.com
stackoverflow.com
stackoverflow.com
www.reddit.com
www.reddit.com
cdn.jsdelivr.net
cdn.jsdelivr.net
fonts.googleapis.com
fonts.googleapis.com
ajax.googleapis.com
ajax.googleapis.com
www.facebook.com
www.facebook.com
www.twitter.com
www.twitter.com
www.amazon.com
www.amazon.com
```

### Step 3: Identify Suspicious Queries
I saw normal queries like Google,Cloudflare,facebook...but wait, there is suspicious queries like `x091337ff-00`??

Found DNS queries with pattern: `x091337ff-[sequence]-04-[hex_data].[domain]`

Bingo! The `x091337ff` was clearly something has to be done with DNS tunelling.

### Step 4: Extract and Decode Flag
Now for the next part which as usual my buddy Deepseek walk me through the process:

First i need to extract the hex data from the query:
```bash
tshark -r challenge.pcap -Y "dns.qry.name contains \"x091337ff\"" -T fields -e dns.qry.name | sort -u | awk -F'-' '{print $4}' | awk -F'.' '{print $1}' | xxd -r -p | base64 -d
```
Let me break down what this command does:

-`tshark` extracts the suspicious DNS queries

-`sort -u` removes duplicates (thanks DeepSeek for that tip!)

-`awk` pulls out just the hex data part

-`xxd` -r -p converts hex to ASCII

-`base64 -d` decodes the final result

When I ran this... boom! There it was!
### Flag
`Exploit3rs{D33p_P4ck3t_1nsp3ct10n_M4st3r_2024}`
