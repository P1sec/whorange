#!/usr/bin/env python

# whorange - Discover network IP range by sending ARP whohas to various subnets/ips
# 2013 Laurent Ghigonis at P1 Security <laurent@p1sec.com>
# Inspired from 'Erethon' arpois.py and 'TheBits' python-arp-ping

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# XXX fix spacing (coded on another machine)

import os
import sys
import time
import subprocess
import binascii
import socket
import unittest
import netifaces
import select
import random
import argparse
import signal

DEFAULT_INTERVAL = 0.1

def get_rand_mac(original_mac=None):
    if original_mac:
        prefix = [ int(original_mac[0:2], 16),
                   int(original_mac[3:5], 16),
                   int(original_mac[6:8], 16) ]
    else:
        prefix = [ random.randint(0x00, 0xff),
                   random.randint(0x00, 0xff),
                   random.randint(0x00, 0xff) ]
    mac = prefix + [ random.randint(0x00, 0x7f),
                     random.randint(0x00, 0xff),
                     random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

class Whohas:
    PACKETSIZE = 42 # ARP default
    ARPREQUEST = 1
    ARPREPLY = 2

    def __init__(self, src_ip=None, src_mac=None, target_ip=None, arptype=ARPREQUEST, pdu=None):
        self.src_ip = src_ip
        self.src_mac = src_mac
        self.target_ip = target_ip
        self.target_mac = "ff:ff:ff:ff:ff:ff"
        self.arptype = arptype
        self.pdu = pdu
        if pdu:
            self.init_from_pdu(pdu)
        self._compute_ip_range()

    def get_pdu(self):
        ethertype = "\x08\x06"
        type_size_opcode = "\x00\x01\x08\x00\x06\x04\x00\x01"
        p = self._encode_mac(self.target_mac) + self._encode_mac(self.src_mac) \
            + ethertype + type_size_opcode                                     \
            + self._encode_mac(self.src_mac) + socket.inet_aton(self.src_ip)   \
            + self._encode_mac(self.target_mac) + socket.inet_aton(self.target_ip)
        return p

    def init_from_pdu(self, pdu):
        self.arptype = ord(pdu[21])
        self.src_mac = self._decode_mac(pdu[22:28])
        self.src_ip = socket.inet_ntoa(pdu[28:32])
        self.target_mac = self._decode_mac(pdu[32:38])
        self.target_ip = socket.inet_ntoa(pdu[38:43])

    def _compute_ip_range(self):
        self.ip_range = "%s.0/24" % self.target_ip.rsplit('.', 1)[0]

    def _encode_mac(self, mac):
        return binascii.a2b_hex(mac.replace(":", ""))

    def _decode_mac(self, mac_pdu):
        return ':'.join(map(lambda x: "%02X" % ord(x), mac_pdu)).lower()

class Whohas_unittest(unittest.TestCase):
    def test_encode_request(self):
        expected_pdu = binascii.a2b_hex("fffffffffffff0def1f68a1908060001080006040001f0def1f68a19c0a80001ffffffffffffc0a800fe")
        pdu = Whohas("192.168.0.1", "f0:de:f1:f6:8a:19", "192.168.0.254").get_pdu()
        self.assertEquals(pdu, expected_pdu)

    def test_decode_reply(self):
        wh = Whohas(pdu=binascii.a2b_hex("2477037adf8d0026c6715130080600010800060400020026c6715130c0a801012477037adf8dc0a801d5"))
        self.assertTrue(wh)
        self.assertEquals(wh.arptype, Whohas.ARPREPLY)
        self.assertEquals(wh.src_mac, "00:26:c6:71:51:30")
        self.assertEquals(wh.src_ip, "192.168.1.1")
        self.assertEquals(wh.target_mac, "24:77:03:7a:df:8d")
        self.assertEquals(wh.target_ip, "192.168.1.213")

class Whohas_sender:
    TYPEFRAME = 0x0806

    def __init__(self, iface, cb_pdu, spoof_mac=True, times=1):
        def _cb_sigint(num, bt):
            print "catched SIGINT, cleaning up"
            self.close()
            sys.exit(2)

        self.iface = iface
        self.cb_pdu = cb_pdu
        self.spoof_mac = spoof_mac
        self.times = times
        signal.signal(signal.SIGINT, _cb_sigint)
        self.real_mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
        if spoof_mac:
            self._set_rand_mac()
        else:
            self.current_mac = self.real_mac
            self._iface_up()
        self.soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.soc.bind((iface, Whohas_sender.TYPEFRAME))
        self.sent_count = 0

    def send(self, src_ip, target_ip):
        if self.spoof_mac and random.random() > 0.999:
            self._set_rand_mac()
        for i in range(self.times):
            self.soc.send(Whohas(src_ip, self.current_mac, target_ip).get_pdu())
        self.sent_count += 1

    def process_pdus(self, waittime):
        endtime = time.time() + waittime
        while time.time() < endtime:
            while True:
                srecv = select.select([self.soc], [], [], 0.0)
                if srecv[0]: # data
                    data = self.soc.recv(Whohas.PACKETSIZE)
                    try:
                        wh = Whohas(pdu=data)
                    except Exception, e:
                        print "ERROR: failed decoding received pdu:\n%s" % binascii.b2a_hex(data)
                    else:
                        if wh and wh.arptype == Whohas.ARPREPLY:
                            self.cb_pdu(wh)
                else: # timeout
                    time.sleep(waittime/10)
                    break

    def close(self):
        self.soc.close()
        if self.spoof_mac:
            print "restoring real mac %s" % self.real_mac
            subprocess.call(["ifconfig", self.iface, "down"])
            subprocess.call(["ifconfig", self.iface, "hw", "ether", self.real_mac])
            subprocess.call(["ifconfig", self.iface, "up"])
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    def _set_rand_mac(self):
        self.current_mac = get_rand_mac(self.real_mac)
        sys.stdout.write("<newmac=%s>" % self.current_mac)
        sys.stdout.flush()
        subprocess.call(["ifconfig", self.iface, "down"])
        subprocess.call(["ifconfig", self.iface, "hw", "ether", self.current_mac])
        self._iface_up()

    def _iface_up(self):
        subprocess.call(["ifconfig", self.iface, "up"])
        endtime = time.time() + 6
        while True:
            c = subprocess.Popen(["ifconfig", self.iface], stdout=subprocess.PIPE)
            out = c.stdout.read()
            if out.find("RUNNING") > -1:
                break
            if time.time() > endtime:
                raise Exception("timeout waiting for iface to be RUNNING")
            time.sleep(0.2)

class Discover_range:
    MOSTUSED_CLASS_B = ["192.168", "10.0", "172.16"]
    # XXX sets breaks order ! don't use sets. find other way to do '-'
    MOSTUSED_SUBNETS = set([0, 1, 254, 2, 100, 137, 10, 20, 30, 99])
    MOSTUSED_IPS = MOSTUSED_SUBNETS
    NOT_USED_IP = 213

    def __init__(self, iface, wait_interval=None, spoof_mac=True, times=1, debug=False):
        self.wait_interval = wait_interval
        # XXX detect interface type and set different default (wifi=0.1, ether=0.01)
        # XXX if not wait_interval:
        #	self.wait_interval = self._guess_wait_interval(iface)
        self.wait_final = 5 if wait_interval * 30 > 5 else wait_interval * 30
        self.snd = Whohas_sender(iface, self._cb_found, spoof_mac, times)
        print "\n[-] 1. scanning known classB, known classC, known IPs"
        res = self.scan(Discover_range.MOSTUSED_CLASS_B,
                        Discover_range.MOSTUSED_SUBNETS,
                        Discover_range.MOSTUSED_IPS,
                        Discover_range.NOT_USED_IP)
        print "\n[-] 2. scanning known classB, all classC, known IPs"
        res = self.scan(Discover_range.MOSTUSED_CLASS_B,
                        set(range(256)) - Discover_range.MOSTUSED_SUBNETS,
                        Discover_range.MOSTUSED_IPS,
                        Discover_range.NOT_USED_IP)
        print "\n[-] 3. scanning known classB, known classC, all IPs"
        res = self.scan(Discover_range.MOSTUSED_CLASS_B,
                        Discover_range.MOSTUSED_SUBNETS,
                        set(range(256)) - Discover_range.MOSTUSED_IPS,
                        Discover_range.NOT_USED_IP)
        print "\n[-] 4. scanning known classB, all classC, all IPs"
        res = self.scan(Discover_range.MOSTUSED_CLASS_B,
                        set(range(256)) - Discover_range.MOSTUSED_SUBNETS,
                        set(range(256)) - Discover_range.MOSTUSED_IPS,
                        Discover_range.NOT_USED_IP)
        print "\n[*] not found"
        self._finish()

    def scan(self, class_b_list, class_c_list, ip_list, src_ip_digit):
        for class_b in class_b_list:
            print "class B: %s" % class_b
            sys.stdout.write("  class C:")
            for class_c in class_c_list:
                sys.stdout.write(" %d" % class_c)
                sys.stdout.flush()
                src_ip = "%s.%d.%d" % (class_b, class_c, src_ip_digit)
                for d in ip_list:
                    target_ip = "%s.%d.%d" % (class_b, class_c, d)
                    self.snd.send(src_ip, target_ip)
                    self.snd.process_pdus(self.wait_interval)
            sys.stdout.write("\n")
            self.snd.process_pdus(self.wait_interval * 30)

    def _cb_found(self, whohas):
        print "\n[*] found !\n"
        print "IP Range      : %s" % whohas.ip_range
        print "IP answering  : %s" % whohas.src_ip
        print "IP source was : %s" % whohas.target_ip
        self._finish()
        # XXX discover all IPs in the range
        # XXX return True # continue

    def _finish(self):
        self.snd.close()
        sys.exit(0)

if __name__ == "__main__":                                                       
    if os.environ.has_key("UNITTEST"):
        unittest.main()
    else:
        parser = argparse.ArgumentParser(
                description='diprange - Discover network IP range by sending ARP whohas to various subnets/ips',
                epilog="Example: %s wlan0" % sys.argv[0])
        parser.add_argument('-i', action="store", dest='interval', default=DEFAULT_INTERVAL, type=float,
                help="interval between sent packets. Default=%ss" % DEFAULT_INTERVAL)
        parser.add_argument('-r', action="store_true", dest='real_mac', default=False,
                help="use real MAC. Default is to use random MAC and change it with probabilty of 1/1000 at every sent packet.")
        parser.add_argument('-t', action="store", dest='times', default=1, type=int,
                help="send n whohas for 1 IP. default is 1. Can be used to improve scanning on bad quality Wifi networks.")
        parser.add_argument('-v', action="store_true", dest="debug", default=False,
                help="verbose")
        parser.add_argument('interface', action="store", help="Target network interface")
        args = parser.parse_args()

        Discover_range(args.interface, args.interval, not args.real_mac, args.times, args.debug)
