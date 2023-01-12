#!/usr/bin/env python3
#
#  Copyright (c) 2020, The OpenThread Authors.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#
import ipaddress
import logging
import time
import unittest
from ipaddress import IPv6Network

import config
import thread_cert

# Test description:
#   This test verifies that a single OMR and on-link prefix is chosen
#   and advertised when there are multiple Border Routers in the same
#   Thread and infrastructure network.
#
# Topology:
#    ----------------(eth)------------------------------
#           |                  |        |          |
#          BR1 (Leader) ----- BR2 ---- BR3        HOST
#         |  \                 |  \
#        ED1 SED1             ED2 SED2
#

BR1 = 1
BR2 = 2
BR3 = 3
HOST = 4
ED1 = 5
SED1 = 6
ED2 = 7
SED2 = 8

LEASE = 200  # Seconds
KEY_LEASE = 200  # Seconds


class MultiBorderRoutersSrp(thread_cert.TestCase):
    USE_MESSAGE_FACTORY = False

    TOPOLOGY = {
        BR1: {
            'name': 'BR1',
            'allowlist': [BR2, BR3, ED1, SED1],
            'is_otbr': True,
            'version': '1.2',
        },
        BR2: {
            'name': 'BR2',
            'allowlist': [BR1, BR3, ED2, SED2],
            'is_otbr': True,
            'version': '1.2',
        },
        BR3: {
            'name': 'BR3',
            'allowlist': [BR1, BR2],
            'is_otbr': True,
            'version': '1.2',
        },
        HOST: {
            'name': 'Host',
            'is_host': True,
        },
        ED1: {
            'name': 'ED1',
            'allowlist': [BR1],
            'version': '1.2',
            'mode': 'rn',
        },
        SED1: {
            'name': 'SED1',
            'allowlist': [BR1],
            'version': '1.2',
            'mode': 'n',
        },
        ED2: {
            'name': 'ED2',
            'allowlist': [BR2],
            'version': '1.2',
            'mode': 'rn',
        },
        SED2: {
            'name': 'SED2',
            'allowlist': [BR2],
            'version': '1.2',
            'mode': 'n',
        },
    }

    def test(self):
        br1 = self.nodes[BR1]
        br2 = self.nodes[BR2]
        br3 = self.nodes[BR3]
        host = self.nodes[HOST]
        ed1 = self.nodes[ED1]
        sed1 = self.nodes[SED1]
        ed2 = self.nodes[ED2]
        sed2 = self.nodes[SED2]
        sed1.set_pollperiod(3000)
        sed2.set_pollperiod(3000)

        br1.send_command('1111111111111111111111111')
        br2.send_command('2222222222222222222222222')
        br3.send_command('3333333333333333333333333')

        # Initially BR3
        br3.stop_otbr_service()

        host.start(start_radvd=False)
        self.simulator.go(5)

        br1.start()
        self.simulator.go(10)
        self.assertEqual('leader', br1.get_state())
        br1.send_command('srp replication enable')
        br1._expect_done()

        self.simulator.go(5)

        br2.start()
        self.simulator.go(10)
        self.assertEqual('router', br2.get_state())
        br2.send_command('srp replication enable')
        br2._expect_done()

        # while True:
        #     logging.info('ready for debugging')
        #     time.sleep(3)
        #     pass

        ed1.start()
        sed1.start()
        ed2.start()
        sed2.start()
        self.simulator.go(10)
        self.assertEqual('child', ed1.get_state())
        self.assertEqual('child', sed1.get_state())
        self.assertEqual('child', ed2.get_state())
        self.assertEqual('child', sed2.get_state())

        # Step 1: ED1, SED1, ED2, SED2 register services
        ed1.srp_client_set_host_name('ed1-host')
        ed1.srp_client_set_host_address(ed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0])
        ed1.srp_client_add_service('ed1-1', '_ed1._tcp', 11111, priority=1, weight=2, txt_entries=['a=1'])
        ed1.srp_client_enable_auto_start_mode()
        ed1.srp_client_add_service('ed1-2', '_ed1._tcp', 11112, priority=1, weight=2, txt_entries=['a=1'])
        ed1.srp_client_enable_auto_start_mode()

        sed1.srp_client_set_host_name('sed1-host')
        sed1.srp_client_set_host_address(sed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0])
        sed1.srp_client_add_service('sed1', '_sed1._tcp', 22222, priority=1, weight=2)
        sed1.srp_client_enable_auto_start_mode()

        ed2.srp_client_set_host_name('ed2-host')
        ed2.srp_client_set_host_address(ed2.get_ip6_address(config.ADDRESS_TYPE.OMR)[0])
        ed2.srp_client_add_service('ed2', '_ed2._tcp', 33333, priority=1, weight=2)
        ed2.srp_client_enable_auto_start_mode()

        sed2.srp_client_set_host_name('sed2-host')
        sed2.srp_client_set_host_address(sed2.get_ip6_address(config.ADDRESS_TYPE.OMR)[0])
        sed2.srp_client_add_service('sed2', '_sed2._tcp', 44444, priority=1, weight=2, txt_entries=['b=2', 'c=3'])
        sed2.srp_client_enable_auto_start_mode()

        self.simulator.go(10)

        servers = [br1, br2]

        self.assertEqual(len(br1.srp_server_get_services()), 5)
        self.assertEqual(len(br2.srp_server_get_services()), 5)
        self.check_srp_host_and_service(ed1, servers, host_name='ed1-host',
                                        address=ed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='ed1-1',
                                        service_type='_ed1._tcp',
                                        port=11111,
                                        txt_entries=['a=31']
                                        )
        self.check_srp_host_and_service(ed1, servers, host_name='ed1-host',
                                        address=ed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='ed1-2',
                                        service_type='_ed1._tcp',
                                        port=11112,
                                        txt_entries=['a=31']
                                        )
        self.check_srp_host_and_service(sed1, servers, host_name='sed1-host',
                                        address=sed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='sed1',
                                        service_type='_sed1._tcp',
                                        port=22222,
                                        txt_entries=[]
                                        )
        self.check_srp_host_and_service(ed2, servers, host_name='ed2-host',
                                        address=ed2.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='ed2',
                                        service_type='_ed2._tcp',
                                        port=33333,
                                        txt_entries=[]
                                        )
        self.check_srp_host_and_service(sed2, servers, host_name='sed2-host',
                                        address=sed2.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='sed2',
                                        service_type='_sed2._tcp',
                                        port=44444,
                                        txt_entries=['b=32', 'c=33']
                                        )

        # Step 2: ED1 removes service ed1-2
        ed1.srp_client_remove_service('ed1-2', '_ed1._tcp')

        self.simulator.go(5)

        self.assertEqual(len(br1.srp_server_get_services()), 5)
        self.assertEqual(len(br2.srp_server_get_services()), 5)
        self.check_srp_host_and_service(ed1, servers, host_name='ed1-host',
                                        address=ed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='ed1-1',
                                        service_type='_ed1._tcp',
                                        port=11111,
                                        txt_entries=['a=31']
                                        )
        self.check_srp_host_and_service(ed1, servers, service_name='ed1-2', service_type='_ed1._tcp', deleted=True)
        self.check_srp_host_and_service(sed1, servers, host_name='sed1-host',
                                        address=sed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='sed1',
                                        service_type='_sed1._tcp',
                                        port=22222,
                                        txt_entries=[]
                                        )
        self.check_srp_host_and_service(ed2, servers, host_name='ed2-host',
                                        address=ed2.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='ed2',
                                        service_type='_ed2._tcp',
                                        port=33333,
                                        txt_entries=[]
                                        )
        self.check_srp_host_and_service(sed2, servers, host_name='sed2-host',
                                        address=sed2.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='sed2',
                                        service_type='_sed2._tcp',
                                        port=44444,
                                        txt_entries=['b=32', 'c=33']
                                        )

        # Step 3: BR 3 starts
        br3.start_otbr_service()
        br3.start()
        servers = [br1, br2, br3]
        self.simulator.go(10)
        br3.send_command('srp replication enable')
        br3._expect_done()

        # br1.stop_ot_ctl()
        # br2.stop_ot_ctl()
        # br3.stop_ot_ctl()

        # while True:
        #     pass

        self.simulator.go(20)

        logging.info("111111111111111111##########")
        br3.srp_server_get_services()
        logging.info("222222222222222222##########")

        # Step 4: SED2 removes host
        sed2.srp_client_remove_host(remove_key=True)

        self.simulator.go(5)

        # self.assertEqual(len(br1.srp_server_get_services()), 4)
        # self.assertEqual(len(br2.srp_server_get_services()), 4)
        # self.assertEqual(len(br3.srp_server_get_services()), 4)
        self.check_srp_host_and_service(ed1, servers, host_name='ed1-host',
                                        address=ed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='ed1-1',
                                        service_type='_ed1._tcp',
                                        port=11111,
                                        txt_entries=['a=31']
                                        )
        self.check_srp_host_and_service(ed1, [br1], service_name='ed1-2', service_type='_ed1._tcp', deleted=True)
        self.check_srp_host_and_service(sed1, servers, host_name='sed1-host',
                                        address=sed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='sed1',
                                        service_type='_sed1._tcp',
                                        port=22222,
                                        txt_entries=[]
                                        )
        self.check_srp_host_and_service(ed2, servers, host_name='ed2-host',
                                        address=ed2.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='ed2',
                                        service_type='_ed2._tcp',
                                        port=33333,
                                        txt_entries=[]
                                        )

    def check_srp_host_and_service(self, client, servers, host_name='', address='', service_name='', service_type='',
                                   port=0, txt_entries=[], deleted=False):
        client_services = list(filter(lambda s: s['instance'] == service_name and s['name'] == service_type,
                                      client.srp_client_get_services()))

        if deleted:
            self.assertEqual(len(client_services), 0)
        else:
            self.assertEqual(len(client_services), 1)
            client_service = client_services[0]

            # Verify that the client possesses correct service resources.
            self.assertEqual(client_service['name'], service_type)
            self.assertEqual(int(client_service['port']), port)
            self.assertEqual(int(client_service['priority']), 1)
            self.assertEqual(int(client_service['weight']), 2)

            # Verify that the client received a SUCCESS response for the server.
            self.assertEqual(client_service['state'], 'Registered')

        for i, server in enumerate(servers):
            logging.info(f'SERVER ID = {i} services = {server.srp_server_get_services()}')

        for server in servers:
            server_services = list(filter(lambda s: s['instance'] == service_name and s['name'] == service_type,
                                          server.srp_server_get_services()))
            self.assertEqual(len(server_services), 1)
            server_service = server_services[0]

            if deleted:
                self.assertEqual(server_service['deleted'], 'true')
                continue

            # Verify that the server accepted the SRP registration and stores
            # the same service resources.
            self.assertEqual(server_service['deleted'], 'false')
            self.assertEqual(server_service['instance'], client_service['instance'])
            self.assertEqual(server_service['name'], client_service['name'])
            self.assertEqual(server_service['subtypes'], '(null)')
            self.assertEqual(int(server_service['port']), int(client_service['port']))
            self.assertEqual(int(server_service['priority']), int(client_service['priority']))
            self.assertEqual(int(server_service['weight']), int(client_service['weight']))
            # We output value of TXT entry as HEX string.
            self.assertEqual(server_service['TXT'], txt_entries)
            self.assertEqual(server_service['host'], host_name)

            server_hosts = list(filter(lambda h: h['name'] == host_name, server.srp_server_get_hosts()))
            self.assertEqual(len(server_hosts), 1)
            server_host = server_hosts[0]

            self.assertEqual(server_host['deleted'], 'false')
            self.assertEqual(server_host['fullname'], server_service['host_fullname'])
            self.assertEqual(len(server_host['addresses']), 1)
            self.assertEqual(ipaddress.ip_address(server_host['addresses'][0]),
                             ipaddress.ip_address(address))


if __name__ == '__main__':
    unittest.main()
