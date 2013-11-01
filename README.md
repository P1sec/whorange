## whorange - Discover network IP range by sending ARP whohas to various subnets/ips

### Example usage:

```bash
sudo ./tools/whorange.py wlan0
<newmac=24:77:03:52:e6:34>
[-] 1. scanning known classB, known classC, known IPs
class B: 192.168
  class C: 0 1
[*] found !
IP Range      : 192.168.1.0/24
IP answering  : 192.168.1.1
IP source was : 192.168.1.213
restauring real mac 24:77:03:11:22:33
```
