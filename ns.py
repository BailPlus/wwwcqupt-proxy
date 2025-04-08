from dnslib.server import DNSServer,BaseResolver
from dnslib import RR,A,QTYPE,SOA,DNSRecord

class Resolver(BaseResolver):
    @staticmethod
    def get_soa(qname='cy.bail.asia'):
        return RR(qname,QTYPE.SOA,rdata=SOA(
            mname='srv.bail.asia',
            rname='bail.bail.asia',
            times=(1,3600,600,86400,60)
        ))
    @staticmethod
    def get_a(req,ip='127.0.0.1'):
        return RR(req.q.qname,QTYPE.A,rdata=A(ip))
    def resolve(self,req:DNSRecord,handler):
        reply = req.reply()
        if req.q.qname != 'cy.bail.asia':##.matchSuffix('nstest.bail.asia.'):
            reply.header.rcode = 0
            return reply
        match req.q.qtype:
            case 1: ## A
                reply.add_answer(self.get_a(req))
                reply.add_auth(self.get_soa(req.q.qname))
            case 6: ## SOA
                reply.add_answer(self.get_soa())
            case _:
                reply.header.rcode = 0
        return reply
resolver = Resolver()
server = DNSServer(resolver,port=53)
server.start()
