import json
import socket
from dnslib import DNSRecord, QTYPE, DNSError, RR, A
import time


class DNSServer:
    ROOT_SERVERS = ["199.9.14.201", "198.41.0.4", "192.33.4.12", "199.7.91.13",
                    "192.203.230.10", "192.5.5.241", "192.112.36.4",
                    "198.97.190.53", "192.36.148.17", "192.58.128.30",
                    "193.0.14.129", "199.7.83.42", "202.12.27.33"]

    def __init__(self, host):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, 53))
        self.q_type = None
        self.transport = None
        self.cache = {}
        self.fetch_cache()

    def run(self):
        while True:
            data, addr = self.sock.recvfrom(512)
            dns_record = DNSRecord.parse(data)
            q_name = dns_record.q.qname.__str__()

            if dns_record.q.qtype != 1:
                self.sock.sendto(data, addr)
            elif 'multiply' in q_name:
                self.sock.sendto(self.get_multiply_response(dns_record), addr)
            else:
                if q_name in self.cache:
                    reply = self.get_result_from_cache(dns_record, q_name)
                    if reply.a.rdata:
                        self.sock.sendto(reply.pack(), addr)
                        continue
                    else:
                        del self.cache[q_name]
                result = None
                for root_server in DNSServer.ROOT_SERVERS:
                    self.q_type = dns_record.q.qtype
                    result = self.lookup(dns_record, root_server)
                    if result:
                        break
                self.cache_result(q_name, DNSRecord.parse(result))
                self.sock.sendto(result, addr)

    def get_result_from_cache(self, dns_record, q_name):
        reply = dns_record.reply()
        current_time = time.time()
        for answer in self.cache[q_name]:
            if answer[2] + answer[1] - current_time >= 0:
                rr = RR(rname=q_name, rtype=QTYPE.A,
                        rdata=A(answer[0]), ttl=answer[1])
                reply.add_answer(rr)
        return reply

    def cache_result(self, request, result: DNSRecord):
        answers = []
        for rr in result.rr:
            answers.append((rr.rdata.__str__(), rr.ttl, time.time()))
        if len(answers) == 0:
            return
        self.cache[request] = answers
        self.update_cache()

    def update_cache(self):
        with open('cache.json', 'w') as cache:
            json.dump(self.cache, cache)

    def fetch_cache(self):
        try:
            with open('cache.json', 'r') as cache:
                data = json.load(cache)
                if data:
                    self.cache = data
        except FileNotFoundError:
            self.update_cache()

    def lookup(self, dns_record: DNSRecord, zone_ip):
        response = dns_record.send(zone_ip)
        parsed_response = DNSRecord.parse(response)
        if dns_record.header.id != parsed_response.header.id:
            raise DNSError(
                'Response transaction id does not match query transaction id')
        for adr in parsed_response.auth:
            if adr.rtype == 6:
                return response
        if parsed_response.a.rdata:
            return response
        new_zones_ip = self.get_new_zones_ip(parsed_response)
        for new_zone_ip in new_zones_ip:
            ip = self.lookup(dns_record, new_zone_ip)
            if ip:
                return ip
        return None

    def get_new_zones_ip(self, parsed_response):
        new_zones_ip = []
        for adr in parsed_response.ar:
            if adr.rtype == 1:
                new_zones_ip.append(adr.rdata.__repr__())
        if len(new_zones_ip) == 0:
            for adr in parsed_response.auth:
                if adr.rtype == 2:
                    question = DNSRecord.question(adr.rdata.__repr__())
                    pkt = self.lookup(question, DNSServer.ROOT_SERVERS[0])
                    parsed_pkt = DNSRecord.parse(pkt)
                    new_zone_ip = parsed_pkt.a.rdata.__repr__()
                    if new_zone_ip:
                        new_zones_ip.append(new_zone_ip)
        return new_zones_ip

    def get_multiply_response(self, dns_record: DNSRecord):
        mult = 0
        name = dns_record.q.qname.__str__()
        index = name.find('multiply')
        zones = name[:index].split('.')
        for zone in zones:
            try:
                number = int(zone)
                if mult == 0:
                    mult = 1
                mult *= number
            except ValueError:
                continue
        mult %= 256
        reply_ip = f'127.0.0.{mult}'
        reply = dns_record.reply()
        reply.add_answer(RR(dns_record.q.qname, QTYPE.A,
                            rdata=A(reply_ip), ttl=60))
        return reply.pack()


if __name__ == "__main__":
    DNSServer('127.0.0.1').run()
