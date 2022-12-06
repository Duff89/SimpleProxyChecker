import time

import requests
from random import choice


class SimpleProxyChecker:
    def __init__(self, ip: str, port: str, timeout: int = 10):
        self.ip = ip
        self.port = port
        self.timeout = timeout

        self.judges_ip = ['https://api.ipify.org/', ]
        self.judges_azenv = ['http://www.proxy-listen.de/azenv.php',
                             'http://mojeip.net.pl/asdfa/azenv.php',
                             'http://azenv.net/',
                             'http://www.proxyjudge.biz/az.php'
                             ]
        self.my_real_ip = self._get_my_ip()
        self.result_dict = {'ip': self.ip, 'port': self.port}

    def _get_my_ip(self) -> str:
        """Get my real ip"""
        return requests.get(choice(self.judges_ip)).text

    def _check_protocol_get_ip(self):
        """Protocol, proxy_ip, speed"""
        self._work_protocol = []
        self._ip_with_proxy = ''
        for protocol in ['http', 'socks4', 'socks5']:
            proxy = {"http": f"{protocol}://{self.ip}:{self.port}", "https": f"{protocol}://{self.ip}:{self.port}"}
            try:
                start = time.time()
                res = requests.get(choice(self.judges_ip), proxies=proxy, timeout=self.timeout)
                if res.status_code == 200:
                    self.result_dict['speed'] = round(time.time() - start, 2)
                    self._work_protocol.append(protocol)
                    _ip_with_proxy = res.text
                    self._get_anonim_level(protocol)
            except Exception:
                pass
        self.result_dict['type'] = self._work_protocol

    def _get_anonim_level(self, protocol):
        private_headers = [
            'VIA',
            'X-FORWARDED-FOR',
            'X-FORWARDED',
            'FORWARDED-FOR',
            'FORWARDED-FOR-IP',
            'FORWARDED',
            'CLIENT-IP',
            'PROXY-CONNECTION'
        ]
        try:
            proxy = {"http": f"{protocol}://{self.ip}:{self.port}", "https": f"{protocol}://{self.ip}:{self.port}"}

            _res = requests.get(choice(self.judges_azenv), proxies=proxy, timeout=self.timeout)
            _answer = _res.text
            if self.my_real_ip in _answer:
                self.result_dict['anonim_level'] = 'Transparent'
            elif any([i in _res.text for i in private_headers]):
                self.result_dict['anonim_level'] = 'Anonymous'
            else:
                self.result_dict['anonim_level'] = 'High'
        except Exception:
            self.result_dict['anonim_level'] = 'Unknown'

    def get_country(self):
        """Country in iso format"""
        try:
            _res = requests.get(url='https://ip2c.org/' + self.ip)
            if _res.text[0] == '1':
                self.result_dict['geo'] = _res.text.split(';')[1]
            else:
                self.result_dict['geo'] = 'Unknown'
        except:
            self.result_dict['geo'] = 'Unknown'

    def main_check(self) -> dict or bool:
        self._check_protocol_get_ip()
        if not self.result_dict['type']: return False
        self.get_country()
        return self.result_dict
