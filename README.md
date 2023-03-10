# Warzone-RAT-packet-decryptor
Warzone RAT packet decryptor is a tool to detect and decrypt malicious packets related to Warzone RAT malware family from a PCAP file. This application can track all the activity performed by the malicious actor, showing the content of the packets exchanged between the C2 and the infected user.

# Installation
To use the script it is necessary to install the Scapy and Chepy libraries.
```python
pip install scapy
```
```python
pip install chepy
```

# Usage
To analyze the traffic of a PCAP file, just enter the path of your PCAP and set the local port used by the malware.

Example of usage:
```
python3 WarzoneDecryptor.py -s /PATH/TO/YOUR/PCAP.PCAP -p 5200
```
Output example:

```
Warzone RAT activity detected in PCAP!!
Affected packets [14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110]
Packet nº 14 - 192.168.14.10:5200  -->  192.168.14.10:51974
Machine info request detected

Packet nº 16 - 192.168.14.10:51974  -->  192.168.14.10:5200
Detected response from the infected machine

}!=K,މ_ DESKTOP-3S9VQDLEB<

Packet nº 18 - 192.168.14.10:5200  -->  192.168.14.10:51974
Remote Shell request detected

Packet nº 20 - 192.168.14.10:51974  -->  192.168.14.10:5200
Detected response from the infected machine

Microsoft Windows [Versin 10.0.19044.1645]
(c) Microsoft Corporation. Todos los derechos reservados.

C:\Windows\system32>
```

