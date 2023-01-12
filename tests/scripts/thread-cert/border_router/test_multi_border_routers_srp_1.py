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
# BR2 = 2
BR3 = 2
HOST = 3
ED1 = 4
# SED1 = 6
# ED2 = 7
# SED2 = 8

LEASE = 200  # Seconds
KEY_LEASE = 200  # Seconds


class MultiBorderRoutersSrp(thread_cert.TestCase):
    USE_MESSAGE_FACTORY = False

    TOPOLOGY = {
        BR1: {
            'name': 'BR1',
            'allowlist': [BR3, ED1],
            'is_otbr': True,
            'version': '1.2',
        },
        BR3: {
            'name': 'BR3',
            'allowlist': [BR1],
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
    }

    def test(self):
        br1 = self.nodes[BR1]
        br3 = self.nodes[BR3]
        host = self.nodes[HOST]
        ed1 = self.nodes[ED1]

        # Initially BR3
        br3.stop_otbr_service()

        host.start(start_radvd=False)
        self.simulator.go(5)

        br1.start()
        self.simulator.go(5)
        self.assertEqual('leader', br1.get_state())

        self.simulator.go(5)

        ed1.start()
        self.simulator.go(5)
        self.assertEqual('child', ed1.get_state())

        # Step 1: ED1, SED1, ED2, SED2 register services
        ed1.srp_client_set_host_name('ed1-host')
        ed1.srp_client_set_host_address(ed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0])
        ed1.srp_client_add_service('ed1-1', '_ed1._udp', 11111, priority=1, weight=2, txt_entries=['a=1'])
        ed1.srp_client_enable_auto_start_mode()
        ed1.srp_client_add_service('ed1-2', '_ed1._tcp', 11112, priority=1, weight=2, txt_entries=['a=1'])
        ed1.srp_client_enable_auto_start_mode()

        self.simulator.go(10)

        servers = [br1]
        self.check_srp_host_and_service(ed1, servers, host_name='ed1-host',
                                        address=ed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='ed1-1',
                                        service_type='_ed1._udp',
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

        # Step 2: ED1 removes service ed1-2
        ed1.srp_client_remove_service('ed1-2', '_ed1._tcp')

        self.simulator.go(5)

        self.check_srp_host_and_service(ed1, servers, host_name='ed1-host',
                                        address=ed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='ed1-1',
                                        service_type='_ed1._udp',
                                        port=11111,
                                        txt_entries=['a=31']
                                        )
        self.check_srp_host_and_service(ed1, servers, service_name='ed1-2', service_type='_ed1._tcp', deleted=True)

        # Step 3: BR 3 starts
        br3.start_otbr_service()
        br3.start()
        servers = [br1, br3]

        br1.stop_ot_ctl()
        br3.stop_ot_ctl()

        while True:
            pass

        # Step 4: SED2 removes host
        self.simulator.go(5)

        self.assertEqual(len(br1.srp_server_get_services()), 2)
        self.assertEqual(len(br3.srp_server_get_services()), 1)
        self.check_srp_host_and_service(ed1, servers, host_name='ed1-host',
                                        address=ed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0],
                                        service_name='ed1-1',
                                        service_type='_ed1._udp',
                                        port=11111,
                                        txt_entries=['a=31']
                                        )
        self.check_srp_host_and_service(ed1, [br1], service_name='ed1-2', service_type='_ed1._tcp', deleted=True)

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
