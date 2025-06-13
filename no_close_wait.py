#Copyright Bail 2025
#no_close_wait 提取导致网站服务CLOSE_WAIT的ip v1.0_1
#2025.4.9

from abc import ABC,abstractmethod
from libblacklist import BlacklistHandler
import sys,subprocess

class ArgReader:
    _argv:list

    def __init__(self,argv=sys.argv):
        self._argv = argv

    def get_files(self):
        return self._argv[1:]

class IpExtracter:
    @staticmethod
    def extract_ip(s: str) -> set[str]:
        '''从文本中提取恶意ip
    s(str):命令原始输出'''
        evilIps = set()
        rows = s.split('\n')
        for i in rows:
            evilIps.add(
                i.split()[-1].split(':')[0]
            )
        return evilIps

class StringProvider(ABC):
    @abstractmethod
    def __str__(self):
        '''提供命令输出的字符串'''

class FileReader(StringProvider):
    '''读取文件列表中的所有文件'''
    def __init__(self,fnlist:list[str]):
        self.fnlist = fnlist
    def __str__(self):
        content = ''
        for i in self.fnlist:
            with open(i) as file:
                content += file.read()
        return content.strip()

class CommandReader(StringProvider):
    def __str__(self):
        return subprocess.run('ss | grep https',capture_output=True,shell=True,text=True).stdout.strip()
    
class IpBlocker(ABC):
    @abstractmethod
    def block(self,ip:str):
        '''添加ip到黑名单'''
        pass

class BlacklistBlocker(IpBlocker):
    def __init__(self,blacklist_handler):
        self._blacklist_handler = blacklist_handler
    def block(self,ip:str):
        self._blacklist_handler.add(ip)

class IptablesBlocker(IpBlocker):
    def block(self,ip:str):
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])

def main():
    arg_reader = ArgReader()
    string_provider:StringProvider
    ip_extracter = IpExtracter()
    blockers:list[IpBlocker] = [
        BlacklistBlocker(BlacklistHandler()),
        IptablesBlocker()
    ]

    files = arg_reader.get_files()
    if files:
        string_provider = FileReader(files)
    else:
        string_provider = CommandReader()
    ips = ip_extracter.extract_ip(str(string_provider))
    for ip in ips:
        for blocker in blockers:
            blocker.block(ip)
        print(f'Blocked IP: {ip}')

if __name__ == '__main__':
    main()
