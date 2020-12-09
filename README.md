# ICMPack

ICMP Server and Client developed in Python3 for Echo Requests and Responses without dependencies (*root required*).

```
ICMP Echo / Echo Reply Message header info from RFC792 -> http://tools.ietf.org/html/rfc792

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |     Code      |          Checksum             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Identifier          |        Sequence Number        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Data ...
  +-+-+-+-+-
```

## Considerations

### Server Side

The Linux kernel, when it receives an icmp echo request package, by default automatically responds with an icmp echo reply package (without giving us any option to reply). That's why we have to disable icmp responses to be able to send our own with data that differs from that sent by the client. To do this, we do the following:


Disable automatic icmp responses by the kernel (*root required*) editing `/etc/sysctl.conf` file:

- Add the following line to your /etc/sysctl.conf:

```
net.ipv4.icmp_echo_ignore_all=1
```

- Then, run: `sysctl -p` to take effect.

## Examples

* Simple ping as in ping.c 
  * Server: `sudo python3.7 server.py wlp2s0`
  * Client: `sudo python3.7 client.py 192.168.13.37`
* Adding custom data in the data section
  * Server: `sudo python3.7 server.py wlp2s0 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB`
  * Client: `sudo python3.7 client.py 192.168.13.37 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
* Pinging google servers
  * Client: `sudo python3.7 client.py google.com`

## Known Bugs

* Different tests have been made using **localhost** and **lo** interface, but the answers with custom data do not arrive correctly to the client (it is not known why)
* When viewing outgoing and incoming ICMP packets using Wireshark, it is noted that when different custom data is added to responses and requests, Wireshark flags the wrong packet (as opposed to packets with default data), but does not flag the invalid field or why.
* The icmp client works correctly on Windows systems even without administrator privileges, but the icmp server does not, because the implementation is linked to a network interface, which in Windows I have not yet discovered how it is done.

## Support

Tested on Linux (Linux Mint) and Windows 10.

## References

* https://tools.ietf.org/html/rfc792
* https://github.com/mjbright/python3-ping/blob/master/ping.py


Special thanks to L, for his help with some problems
