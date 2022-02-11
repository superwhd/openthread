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
#    ----------------(eth)------------------
#           |                  |     |
#          BR1 (Leader) ----- BR2   HOST
#         |  \                 |  \
#        ED1 SED1             ED2 SED2
#

BR1 = 1
BR2 = 2
HOST = 3
ED1 = 4
SED1 = 5
ED2 = 6
SED2 = 7

LEASE = 200  # Seconds
KEY_LEASE = 200  # Seconds



class MultiBorderRouters(thread_cert.TestCase):
    USE_MESSAGE_FACTORY = False

    TOPOLOGY = {
        BR1: {
            'name': 'BR1',
            'allowlist': [BR2, ED1, SED1],
            'is_otbr': True,
            'version': '1.2',
        },
        BR2: {
            'name': 'BR2',
            'allowlist': [BR1, ED2, SED2],
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
        host = self.nodes[HOST]
        ed1 = self.nodes[ED1]
        sed1 = self.nodes[SED1]
        ed2 = self.nodes[ED2]
        sed2 = self.nodes[SED2]
        sed1.set_pollperiod(3000)
        sed2.set_pollperiod(3000)

        host.start(start_radvd=False)
        self.simulator.go(5)

        br1.start()
        self.simulator.go(5)
        self.assertEqual('leader', br1.get_state())

        self.simulator.go(5)

        br2.start()
        self.simulator.go(5)
        self.assertEqual('router', br2.get_state())

        ed1.start()
        sed1.start()
        ed2.start()
        sed2.start()
        self.simulator.go(5)
        self.assertEqual('child', ed1.get_state())
        self.assertEqual('child', sed1.get_state())
        self.assertEqual('child', ed2.get_state())
        self.assertEqual('child', sed2.get_state())

        br1.srp_server_set_enabled(True)
        br1.srp_server_set_lease_range(LEASE, LEASE, KEY_LEASE, KEY_LEASE)
        br2.srp_server_set_enabled(True)
        br2.srp_server_set_lease_range(LEASE, LEASE, KEY_LEASE, KEY_LEASE)
        self.simulator.go(3)
        self.assertEqual(br1.srp_server_get_state(), 'running')
        self.assertEqual(br2.srp_server_get_state(), 'running')

        ed1.srp_client_set_host_name('ed1-host')
        ed1.srp_client_set_host_address(ed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0])
        ed1.srp_client_add_service('ed1', '_ed1._tcp', 12345)
        ed1.srp_client_enable_auto_start_mode()

        sed1.srp_client_set_host_name('sed1-host')
        sed1.srp_client_set_host_address(sed1.get_ip6_address(config.ADDRESS_TYPE.OMR)[0])
        sed1.srp_client_add_service('sed1', '_sed1._tcp', 12345)
        sed1.srp_client_enable_auto_start_mode()

        ed2.srp_client_set_host_name('ed2-host')
        ed2.srp_client_set_host_address(ed2.get_ip6_address(config.ADDRESS_TYPE.OMR)[0])
        ed2.srp_client_add_service('ed2', '_ed2._tcp', 12345)
        ed2.srp_client_enable_auto_start_mode()

        sed2.srp_client_set_host_name('sed2-host')
        sed2.srp_client_set_host_address(sed2.get_ip6_address(config.ADDRESS_TYPE.OMR)[0])
        sed2.srp_client_add_service('sed2', '_sed2._tcp', 12345)
        sed2.srp_client_enable_auto_start_mode()

        self.simulator.go(10)

        logging.info(f'BR1 services = {br1.srp_server_get_services()}')
        logging.info(f'BR2 services = {br2.srp_server_get_services()}')

        logging.info(f'ed1 services = {ed1.srp_client_get_services()}')
        logging.info(f'sed1 services = {sed1.srp_client_get_services()}')

        logging.info(f'ed2 services = {ed2.srp_client_get_services()}')
        logging.info(f'sed2 services = {sed2.srp_client_get_services()}')

        logging.info(f'host browsing ed1 = {host.browse_mdns_services("_ed1._tcp")}')
        logging.info(f'host browsing sed1 = {host.browse_mdns_services("_sed1._tcp")}')
        logging.info(f'host browsing ed2 = {host.browse_mdns_services("_ed2._tcp")}')
        logging.info(f'host browsing sed2 = {host.browse_mdns_services("_sed2._tcp")}')

        while True:
            pass







if __name__ == '__main__':
    unittest.main()
