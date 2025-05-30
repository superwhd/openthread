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
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
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
import functools
import ipaddress
import logging
import re
from collections import Counter
from typing import Callable, List, Literal, Collection, Union, Tuple, Optional, Dict, Pattern, Any

from . import connectors
from .command_handlers import OTCommandHandler, OtCliCommandRunner, OtbrSshCommandRunner, OtbrAdbTcpCommandRunner
from .command_handlers import OtbrAdbUsbCommandRunner
from .connectors import Simulator
from .errors import UnexpectedCommandOutput, ExpectLineTimeoutError, CommandError, InvalidArgumentsError
from .types import ChildId, Rloc16, Ip4Addr, Ip6Addr, ThreadState, PartitionId, DeviceMode, RouterId, SecurityPolicy, Ip6Prefix
from .types import RouterTableEntry, NetifIdentifier
from .utils import match_line, constant_property, bits_set


class OTCI(object):
    """
    This class represents an OpenThread Controller Interface instance that provides versatile interfaces to
    manipulate an OpenThread device.
    """

    DEFAULT_EXEC_COMMAND_RETRY = 4  # A command is retried 4 times if failed.

    __exec_command_retry = DEFAULT_EXEC_COMMAND_RETRY

    def __init__(self, otcmd: OTCommandHandler):
        """
        This method initializes an OTCI instance.

        :param otcmd: An OpenThread Command Handler instance to execute OpenThread CLI commands.
        """
        self.__otcmd: OTCommandHandler = otcmd
        self.__logger = logging.getLogger(name=str(self))

    def __repr__(self):
        """Gets the string representation of the OTCI instance."""
        return repr(self.__otcmd)

    def set_filter(self, filter: re.Pattern[str]):
        self.__otcmd.set_filter(filter)

    def wait(self, duration: float, expect_line: Optional[Union[str, Pattern[str], Collection[str]]] = None):
        """Wait for a given duration.

        :param duration: The duration (in seconds) wait for.
        :param expect_line: The line expected to output if given.
                            Raise ExpectLineTimeoutError if expect_line is not found within the given duration.
        """
        self.log('info', "wait for %.3f seconds", duration)
        if expect_line is None:
            self.__otcmd.wait(duration)
        else:
            success = False

            while duration > 0:
                output = self.__otcmd.wait(1)
                if any(match_line(line, expect_line) for line in output):
                    success = True
                    break

                duration -= 1

            if not success:
                raise ExpectLineTimeoutError(expect_line)

    def close(self):
        """Close the OTCI instance."""
        self.__otcmd.close()

    def execute_command(self,
                        cmd: str,
                        timeout: float = 10,
                        silent: bool = False,
                        already_is_ok: bool = True,
                        ignore_result: bool = False) -> List[str]:
        for i in range(self.__exec_command_retry + 1):
            try:
                return self.__execute_command(cmd,
                                              timeout,
                                              silent,
                                              already_is_ok=already_is_ok,
                                              ignore_result=ignore_result)
            except Exception as e:
                self.wait(2)
                if i == self.__exec_command_retry:
                    raise e from None
        assert False

    def __execute_command(self,
                          cmd: str,
                          timeout: float = 10,
                          silent: bool = False,
                          already_is_ok: bool = True,
                          ignore_result: bool = False) -> List[str]:
        """Execute the OpenThread CLI command.

        :param cmd: The command to execute.
        :param timeout: The command timeout.
        :param silent: Whether to run the command silent without logging.
        :returns: The command output as a list of lines.
        """
        if not silent:
            self.log('info', '> %s', cmd)

        output = self.__otcmd.execute_command(cmd, timeout)

        if not silent:
            for line in output:
                self.log('info', '%s', line)

        if cmd in ('reset', 'factoryreset') or ignore_result:
            return output

        if output[-1] == 'Done' or (already_is_ok and output[-1] == 'Error 24: Already'):
            output = output[:-1]
            return output
        else:
            raise CommandError(cmd, output)

    def execute_platform_command(self, cmd: str, timeout: float = 10, silent: bool = False) -> List[str]:
        """Execute the platform command.

        :param cmd: The command to execute.
        :param timeout: The command timeout.
        :param silent: Whether to run the command silent without logging.
        :returns: The command output as a list of lines.
        """
        if not silent:
            self.log('info', '> %s', cmd)

        output = self.__otcmd.execute_platform_command(cmd, timeout)

        if not silent:
            for line in output:
                self.log('info', '%s', line)

        return output

    def set_execute_command_retry(self, n: int):
        assert n >= 0
        self.__exec_command_retry = n

    def shell(self, cmd: str, timeout: float = 10):
        self.log('info', '# %s', cmd)
        output = self.__otcmd.shell(cmd, timeout=timeout)
        for line in output:
            self.log('info', '%s', line)
        return output

    def set_logger(self, logger: Optional[logging.Logger]):
        """Set the logger for the OTCI instance, or None to disable logging."""
        self.__logger = logger

    def log(self, level: str, fmt: str, *args: Any, **kwargs: Any):
        if self.__logger is not None:
            getattr(self.__logger, level)('(%s) ' + fmt, repr(self), *args, **kwargs)

    def set_line_read_callback(self, callback: Optional[Callable[[str], Any]]):
        """Set the callback that will be called for each line output by the CLI."""
        self.__otcmd.set_line_read_callback(callback)

    #
    # Constant properties
    #
    @constant_property
    def version(self):
        """Returns the firmware version.

        (e.g. "OPENTHREAD/20191113-01411-gb2d66e424-dirty; SIMULATION; Nov 14 2020 14:24:38")
        """
        return self.__parse_str(self.execute_command('version'))

    @constant_property
    def thread_version(self):
        """Get the Thread Version number."""
        return self.__parse_int(self.execute_command('thread version'))

    @constant_property
    def api_version(self):
        """Get API version number."""
        try:
            return self.__parse_int(self.execute_command('version api'))
        except ValueError:
            # If the device does not have `version api` command, it will print the firmware version,
            # which would lead to ValueError.
            return 0

    #
    # Vendor operations
    #
    def get_vendor_name(self) -> str:
        return self.__parse_str(self.execute_command('vendor name'))

    def set_vendor_name(self, name: str):
        self.execute_command(f'vendor name {name}')

    def get_vendor_model(self) -> str:
        return self.__parse_str(self.execute_command('vendor model'))

    def set_vendor_model(self, model: str):
        self.execute_command(f'vendor model {model}')

    def get_vendor_sw_version(self) -> str:
        return self.__parse_str(self.execute_command('vendor swversion'))

    def set_vendor_sw_version(self, version: str):
        self.execute_command(f'vendor swversion {version}')

    #
    # Basic device operations
    #
    def ifconfig_up(self):
        """Bring up the IPv6 interface."""
        self.execute_command('ifconfig up')

    def ifconfig_down(self):
        """Bring down the IPv6 interface."""
        self.execute_command('ifconfig down')

    def get_ifconfig_state(self) -> bool:
        """Get the status of the IPv6 interface."""
        return self.__parse_values(self.execute_command('ifconfig'), up=True, down=False)

    def thread_start(self):
        """Enable Thread protocol operation and attach to a Thread network."""
        self.execute_command('thread start')

    def thread_stop(self):
        """Disable Thread protocol operation and detach from a Thread network."""
        self.execute_command('thread stop')

    def reset(self):
        """Signal a platform reset."""
        self.execute_command('reset')

    def factory_reset(self):
        """Delete all stored settings, and signal a platform reset."""
        self.execute_command('factoryreset')

    #
    # Network Operations
    #
    _PING_STATISTICS_PATTERN = re.compile(
        r'^(?P<transmitted>\d+) packets transmitted, (?P<received>\d+) packets received.' +
        r'(?: Packet loss = (?P<loss>\d+\.\d+)%.)?' +
        r'(?: Round-trip min/avg/max = (?P<min>\d+)/(?P<avg>\d+\.\d+)/(?P<max>\d+) ms.)?$')

    def ping(self,
             dst: Union[str, Ip6Addr],
             src: Union[str, Ip6Addr] = "",
             size: int = 8,
             count: int = 1,
             interval: float = 1,
             hoplimit: int = 64,
             timeout: float = 3) -> Dict[str, Union[int, float, Dict[str, Union[int, float]]]]:
        """Send an ICMPv6 Echo Request.
        The default arguments are consistent with
            https://github.com/openthread/openthread/blob/main/src/core/utils/ping_sender.hpp.

        :param dst: The target IPv6 address to ping.
        :param src: The source IPv6 address of the echo request.
        :param size: The number of data bytes in the payload. Default is 8.
        :param count: The number of ICMPv6 Echo Requests to be sent. Default is 1.
        :param interval: The interval between two consecutive ICMPv6 Echo Requests in seconds. The value may have
                         fractional form, for example 0.5. Default is 1.
        :param hoplimit: The hoplimit of ICMPv6 Echo Request to be sent. Default is 64. See
                         OPENTHREAD_CONFIG_IP6_HOP_LIMIT_DEFAULT in src/core/config/ip6.h.
        :param timeout: The maximum duration in seconds for the ping command to wait after the final echo request is
                        sent. Default is 3.
        """
        cmd = f'ping {"" if not src else "-I %s" % src} {dst} {size} {count} {interval} {hoplimit} {timeout}'

        timeout_allowance = 3
        lines = self.execute_command(cmd, timeout=(count - 1) * interval + timeout + timeout_allowance)

        statistics: Dict[str, Union[int, float, Dict[str, Union[int, float]]]] = {}
        for line in lines:
            m = OTCI._PING_STATISTICS_PATTERN.match(line)
            if m is not None:
                if m.group('transmitted') is not None:
                    statistics['transmitted_packets'] = int(m.group('transmitted'))
                    statistics['received_packets'] = int(m.group('received'))
                if m.group('loss') is not None:
                    statistics['packet_loss'] = float(m.group('loss')) / 100
                if m.group('min') is not None:
                    statistics['round_trip_time'] = {
                        'min': int(m.group('min')),
                        'avg': float(m.group('avg')),
                        'max': int(m.group('max'))
                    }
        return statistics

    def ping_stop(self):
        """Stop sending ICMPv6 Echo Requests."""
        self.execute_command('ping stop')

    def discover(self, channel: Optional[int] = None) -> List[Dict[str, Any]]:
        """Perform an MLE Discovery operation."""
        return self.__scan_networks('discover', channel)

    def scan(self, channel: Optional[int] = None) -> List[Dict[str, Any]]:
        """Perform an IEEE 802.15.4 Active Scan."""
        return self.__scan_networks('scan', channel)

    def __scan_networks(self, cmd: str, channel: Optional[int] = None) -> List[Dict[str, Any]]:
        if channel is not None:
            cmd += f' {channel}'

        output = self.execute_command(cmd, timeout=10)
        if len(output) < 2:
            raise UnexpectedCommandOutput(output)

        networks: List[Dict[str, Union[str, bool, int]]] = []
        for line in output[2:]:
            fields = line.strip().split('|')

            try:
                _, J, netname, extpanid, panid, extaddr, ch, dbm, lqi, _ = fields
            except Exception:
                logging.warning('ignored output: %r', line)
                continue

            networks.append({
                'joinable': bool(int(J)),
                'network_name': netname.strip(),
                'extpanid': extpanid,
                'panid': int(panid, 16),
                'extaddr': extaddr,
                'channel': int(ch),
                'dbm': int(dbm),
                'lqi': int(lqi),
            })

        return networks

    def scan_energy(self, duration: Optional[float] = None, channel: Optional[int] = None) -> Dict[int, int]:
        """Perform an IEEE 802.15.4 Energy Scan."""
        cmd = 'scan energy'
        if duration is not None:
            cmd += f' {duration * 1000:d}'

        if channel is not None:
            cmd += f' {channel}'

        output = self.execute_command(cmd, timeout=10)
        if len(output) < 2:
            raise UnexpectedCommandOutput(output)

        channels: Dict[int, int] = {}
        for line in output[2:]:
            fields = line.strip().split('|')

            _, Ch, RSSI, _ = fields
            channels[int(Ch)] = int(RSSI)

        return channels

    def mac_send_data_request(self):
        """Instruct an Rx-Off-When-Idle device to send a Data Request mac frame to its parent."""
        self.execute_command('mac send datarequest')

    def mac_send_empty_data(self):
        """Instruct an Rx-Off-When-Idle device to send a Empty Data mac frame to its parent."""
        self.execute_command('mac send emptydata')

    # TODO: fake /a/an <dst-ipaddr> <target> <meshLocalIid>
    # TODO: sntp query

    #
    # Set or get device/network parameters
    #

    def get_mode(self) -> str:
        """Get the Thread Device Mode value.

            -: no flags set (rx-off-when-idle, minimal Thread device, stable network data)
            r: rx-on-when-idle
            d: Full Thread Device
            n: Full Network Data
        """
        return self.__parse_str(self.execute_command('mode'))

    def set_mode(self, mode: str):
        """Set the Thread Device Mode value.

            -: no flags set (rx-off-when-idle, minimal Thread device, stable network data)
            r: rx-on-when-idle
            d: Full Thread Device
            n: Full Network Data
        """
        self.execute_command(f'mode {DeviceMode(mode)}')

    def get_extaddr(self) -> str:
        """Get the IEEE 802.15.4 Extended Address."""
        return self.__parse_extaddr(self.execute_command('extaddr'))

    def set_extaddr(self, extaddr: str):
        """Set the IEEE 802.15.4 Extended Address."""
        self.__validate_hex64b(extaddr)
        self.execute_command(f'extaddr {extaddr}')

    def get_eui64(self) -> str:
        """Get the factory-assigned IEEE EUI-64."""
        return self.__parse_eui64(self.execute_command('eui64'))

    def set_extpanid(self, extpanid: str):
        """Set the Thread Extended PAN ID value."""
        self.__validate_extpanid(extpanid)
        self.execute_command(f'extpanid {extpanid}')

    def get_extpanid(self) -> str:
        """Get the Thread Extended PAN ID value."""
        return self.__parse_extpanid(self.execute_command('extpanid'))

    def set_channel(self, ch: int):
        """Set the IEEE 802.15.4 Channel value."""
        self.execute_command('channel %d' % ch)

    def get_channel(self):
        """Get the IEEE 802.15.4 Channel value."""
        return self.__parse_int(self.execute_command('channel'))

    def get_preferred_channel_mask(self) -> int:
        """Get preferred channel mask."""
        return self.__parse_int(self.execute_command('channel preferred'))

    def get_supported_channel_mask(self):
        """Get supported channel mask."""
        return self.__parse_int(self.execute_command('channel supported'))

    def get_panid(self):
        """Get the IEEE 802.15.4 PAN ID value."""
        return self.__parse_int(self.execute_command('panid'), 16)

    def set_panid(self, panid: int):
        """Get the IEEE 802.15.4 PAN ID value."""
        self.execute_command('panid %d' % panid)

    def set_network_name(self, name: str):
        """Set network name."""
        self.execute_command('networkname %s' % self.__escape_escapable(name))

    def get_network_name(self):
        """Get network name."""
        return self.__parse_str(self.execute_command('networkname'))

    def get_network_key(self) -> str:
        """Get the network key."""
        return self.__parse_network_key(self.execute_command(self.__detect_networkkey_cmd()))

    def set_network_key(self, networkkey: str):
        """Set the network key."""
        self.__validate_network_key(networkkey)
        cmd = self.__detect_networkkey_cmd()
        self.execute_command(f'{cmd} {networkkey}')

    def get_key_sequence_counter(self) -> int:
        """Get the Thread Key Sequence Counter."""
        return self.__parse_int(self.execute_command('keysequence counter'))

    def set_key_sequence_counter(self, counter: int):
        """Set the Thread Key Sequence Counter."""
        self.execute_command(f'keysequence counter {counter}')

    def get_key_sequence_guard_time(self) -> int:
        """Get Thread Key Switch Guard Time (in hours)."""
        return self.__parse_int(self.execute_command('keysequence guardtime'))

    def set_key_sequence_guard_time(self, hours: int):
        """Set Thread Key Switch Guard Time (in hours) 0 means Thread Key Switch immediately if key index match."""
        self.execute_command(f'keysequence guardtime {hours}')

    def get_cca_threshold(self) -> int:
        """Get the CCA threshold in dBm measured at antenna connector per IEEE 802.15.4 - 2015 section 10.1.4."""
        output = self.execute_command('ccathreshold')
        val = self.__parse_str(output)
        if not val.endswith(' dBm'):
            raise UnexpectedCommandOutput(output)

        return int(val[:-4])

    def set_cca_threshold(self, val: int):
        """Set the CCA threshold measured at antenna connector per IEEE 802.15.4 - 2015 section 10.1.4."""
        self.execute_command(f'ccathreshold {val}')

    def get_promiscuous(self) -> bool:
        """Get radio promiscuous property."""
        return self.__parse_Enabled_or_Disabled(self.execute_command('promiscuous'))

    def enable_promiscuous(self):
        """Enable radio promiscuous operation and print raw packet content."""
        self.execute_command('promiscuous enable')

    def disable_promiscuous(self):
        """Disable radio promiscuous operation."""
        self.execute_command('promiscuous disable')

    def get_txpower(self) -> int:
        """Get the transmit power in dBm."""
        line = self.__parse_str(self.execute_command('txpower'))
        if not line.endswith(' dBm'):
            raise UnexpectedCommandOutput([line])

        return int(line.split()[0])

    def set_txpower(self, val: int):
        """Set the transmit power in dBm."""
        self.execute_command(f'txpower {val}')

    def set_ml_iid(self, ml_iid: str):
        """Set the Mesh Local IID."""
        self.__validate_iid(ml_iid)
        self.execute_command(f'mliid {ml_iid}')

    # TODO: fem
    # TODO: fem lnagain
    # TODO: fem lnagain <LNA gain>
    # TODO: mac retries direct
    # TODO: mac retries direct
    # TODO: mac retries indirect
    # TODO: mac retries indirect <number>

    #
    # Basic Node states and properties
    #

    def get_state(self) -> ThreadState:
        """Get the current Thread state."""
        return ThreadState(self.__parse_str(self.execute_command('state')))

    def set_state(self, state: str):
        """Try to switch to state detached, child, router or leader."""
        self.execute_command(f'state {state}')

    def get_rloc16(self) -> Rloc16:
        """Get the Thread RLOC16 value."""
        return Rloc16(self.__parse_int(self.execute_command('rloc16'), 16))

    def get_router_id(self) -> int:
        """Get the Thread Router ID value."""
        return self.get_rloc16() >> 10

    def prefer_router_id(self, routerid: int):
        """Prefer a Router ID when solicit router id from Leader."""
        self.execute_command(f'preferrouterid {routerid}')

    def is_singleton(self) -> bool:
        return self.__parse_values(self.execute_command('singleton'), true=True, false=False)

    def disable_tvcheck(self):
        """Disable the version check when upgrading to router."""
        self.execute_command('tvcheck disable')

    #
    # RCP related utilities
    #

    def get_rcp_version(self):
        return self.__parse_str(self.execute_command('rcp version'))

    #
    # Unsecure port utilities
    #

    def get_unsecure_ports(self) -> List[int]:
        """all ports from the allowed unsecured port list."""
        return self.__parse_int_list(self.execute_command('unsecureport get'))

    def add_unsecure_port(self, port: int):
        """Add a port to the allowed unsecured port list."""
        self.execute_command(f'unsecureport add {port}')

    def remove_unsecure_port(self, port: int):
        """Remove a port from the allowed unsecured port list."""
        self.execute_command(f'unsecureport remove {port}')

    def clear_unsecure_ports(self):
        """Remove all ports from the allowed unsecured port list."""
        self.execute_command('unsecureport remove all')

    #
    # Leader configurations
    #

    def get_preferred_partition_id(self) -> PartitionId:
        """Get the preferred Thread Leader Partition ID."""
        return PartitionId(self.__parse_int(self.execute_command(self.__get_partition_preferred_cmd())))

    def set_preferred_partition_id(self, parid: int):
        """Set the preferred Thread Leader Partition ID."""
        self.execute_command(f'{self.__get_partition_preferred_cmd()} {parid}')

    def __get_partition_preferred_cmd(self) -> str:
        """"""
        return 'partitionid preferred' if self.api_version >= 51 else 'leaderpartitionid'

    def get_leader_weight(self) -> int:
        """Get the Thread Leader Weight."""
        return self.__parse_int(self.execute_command('leaderweight'))

    def set_leader_weight(self, weight: int):
        """Set the Thread Leader Weight."""
        self.execute_command(f'leaderweight {weight}')

    __LEADER_DATA_KEY_MAP = {
        'Partition ID': 'partition_id',
        'Weighting': 'weight',
        'Data Version': 'data_ver',
        'Stable Data Version': 'stable_data_ver',
        'Leader Router ID': 'leader_id',
    }

    def get_leader_data(self) -> Dict[str, int]:
        """Get the Thread Leader Data."""
        data: Dict[str, int] = {}
        output = self.execute_command('leaderdata')

        try:
            for line in output:
                k, v = line.split(': ')
                data[OTCI.__LEADER_DATA_KEY_MAP[k]] = int(v)
        except KeyError:
            raise UnexpectedCommandOutput(output)

        return data

    #
    # Router configurations
    #

    def get_router_selection_jitter(self):
        """Get the ROUTER_SELECTION_JITTER value."""
        return self.__parse_int(self.execute_command('routerselectionjitter'))

    def set_router_selection_jitter(self, jitter: int):
        """Set the ROUTER_SELECTION_JITTER value."""
        self.execute_command(f'routerselectionjitter {jitter}')

    def get_network_id_timeout(self) -> int:
        """Get the NETWORK_ID_TIMEOUT parameter used in the Router role."""
        return self.__parse_int(self.execute_command('networkidtimeout'))

    def set_network_id_timeout(self, timeout: int):
        """Set the NETWORK_ID_TIMEOUT parameter used in the Router role."""
        self.execute_command(f'networkidtimeout {timeout}')

    def get_parent_priority(self) -> int:
        """Get the assigned parent priority value, -2 means not assigned."""
        return self.__parse_int(self.execute_command('parentpriority'))

    def set_parent_priority(self, priority: int):
        """Set the assigned parent priority value: 1, 0, -1 or -2."""
        self.execute_command(f'parentpriority {priority}')

    def get_router_upgrade_threshold(self) -> int:
        """Get the ROUTER_UPGRADE_THRESHOLD value."""
        return self.__parse_int(self.execute_command('routerupgradethreshold'))

    def set_router_upgrade_threshold(self, threshold: int):
        """Set the ROUTER_UPGRADE_THRESHOLD value."""
        self.execute_command(f'routerupgradethreshold {threshold}')

    def get_router_downgrade_threshold(self):
        """Set the ROUTER_DOWNGRADE_THRESHOLD value."""
        return self.__parse_int(self.execute_command('routerdowngradethreshold'))

    def set_router_downgrade_threshold(self, threshold: int):
        """Get the ROUTER_DOWNGRADE_THRESHOLD value."""
        self.execute_command(f'routerdowngradethreshold {threshold}')

    def get_router_eligible(self) -> bool:
        """Indicates whether the router role is enabled or disabled."""
        return self.__parse_Enabled_or_Disabled(self.execute_command('routereligible'))

    def enable_router_eligible(self):
        """Disable the router role."""
        self.execute_command('routereligible enable')

    def disable_router_eligible(self):
        """Disable the router role."""
        self.execute_command('routereligible disable')

    def get_router_list(self) -> List[RouterId]:
        """Get allocated Router IDs."""
        line = self.__parse_str(self.execute_command('router list'))
        return list(map(RouterId, line.strip().split()))

    def get_router_table(self) -> Dict[RouterId, RouterTableEntry]:
        """table of routers."""
        output = self.execute_command('router table')
        if len(output) < 2:
            raise UnexpectedCommandOutput(output)

        #
        # Example output:
        #
        # | ID | RLOC16 | Next Hop | Path Cost | LQ In | LQ Out | Age | Extended MAC     |
        # +----+--------+----------+-----------+-------+--------+-----+------------------+
        # | 21 | 0x5400 |       21 |         0 |     3 |      3 |   5 | d28d7f875888fccb |
        # | 56 | 0xe000 |       56 |         0 |     0 |      0 | 182 | f2d92a82c8d8fe43 |
        # Done
        #

        headers = self.__split_table_row(output[0])

        table: Dict[RouterId, RouterTableEntry] = {}
        for line in output[2:]:
            line = line.strip()
            if not line:
                continue

            fields = self.__split_table_row(line)
            if len(fields) != len(headers):
                raise UnexpectedCommandOutput(output)

            def col(col_name: str):
                return self.__get_table_col(col_name, headers, fields)

            id = col('ID')

            table[RouterId(id)] = router = RouterTableEntry({
                'id': RouterId(id),
                'rloc16': Rloc16(col('RLOC16'), 16),
                'next_hop': int(col('Next Hop')),
                'path_cost': int(col('Path Cost')),
                'lq_in': int(col('LQ In')),
                'lq_out': int(col('LQ Out')),
                'age': int(col('Age')),
                'extaddr': col('Extended MAC'),
            })

            if 'Link' in headers:
                router['link'] = int(col('Link'))
            else:
                # support older version of OT which does not output `Link` field
                router['link'] = self.get_router_info(RouterId(id), silent=True)['link']

        return table

    def get_router_info(self, id: int, silent: bool = False) -> RouterTableEntry:
        cmd = f'router {id}'
        output = self.execute_command(cmd, silent=silent)
        items = [line.strip().split(': ') for line in output]

        headers = [h for h, _ in items]
        fields = [f for _, f in items]

        def col(col_name: str) -> str:
            return self.__get_table_col(col_name, headers, fields)

        return RouterTableEntry({
            'id': RouterId(id),
            'rloc16': Rloc16(col('Rloc'), 16),
            'alloc': int(col('Alloc')),
            'next_hop': int(col('Next Hop'), 16) >> 10,  # convert RLOC16 to Router ID
            'link': int(col('Link')),
        })

    #
    # Router utilities: Child management
    #

    def get_child_table(self) -> Dict[ChildId, Dict[str, Union[ChildId, Rloc16, int, str]]]:
        """Get the table of attached children."""
        output = self.execute_command('child table')
        if len(output) < 2:
            raise UnexpectedCommandOutput(output)

        #
        # Example output:
        # | ID  | RLOC16 | Timeout    | Age        | LQ In | C_VN |R|D|N|Ver|CSL|QMsgCnt| Extended MAC     |
        # +-----+--------+------------+------------+-------+------+-+-+-+---+---+-------+------------------+
        # |   1 | 0xc801 |        240 |         24 |     3 |  131 |1|0|0|  3| 0 |     0 | 4ecede68435358ac |
        # |   2 | 0xc802 |        240 |          2 |     3 |  131 |0|0|0|  3| 1 |     0 | a672a601d2ce37d8 |
        # Done
        #

        headers = self.__split_table_row(output[0])

        table: Dict[ChildId, Dict[str, Union[ChildId, Rloc16, int, str]]] = {}
        for line in output[2:]:
            line = line.strip()
            if not line:
                continue

            fields = self.__split_table_row(line)

            def col(col_name: str):
                return self.__get_table_col(col_name, headers, fields)

            id = int(col("ID"))
            r, d, n = int(col("R")), int(col("D")), int(col("N"))

            #
            # Device mode flags:
            #
            # r: rx-on-when-idle
            # d: Full Thread Device
            # n: Full Network Data
            # -: no flags set (rx-off-when-idle, minimal Thread device, stable network data)
            mode = DeviceMode(
                f'{"r" if r else ""}{"d" if d else ""}{"n" if n else ""}{"-" if r == d == n == 0 else ""}')

            child: Dict[str, Union[ChildId, Rloc16, int, str]] = {
                'id': ChildId(id),
                'rloc16': Rloc16(col('RLOC16'), 16),
                'timeout': int(col('Timeout')),
                'age': int(col('Age')),
                'lq_in': int(col('LQ In')),
                'c_vn': int(col('C_VN')),
                'mode': mode,
                'extaddr': col('Extended MAC')
            }

            if 'Ver' in headers:
                child['ver'] = int(col('Ver'))

            if 'CSL' in headers:
                child['csl'] = bool(int(col('CSL')))

            if 'QMsgCnt' in headers:
                child['qmsgcnt'] = int(col('QMsgCnt'))

            if 'Suprvsn' in headers:
                child['suprvsn'] = int(col('Suprvsn'))

            table[ChildId(id)] = child

        return table

    #
    # DNS server & client utilities
    #

    _IPV6_SERVER_PORT_PATTERN = re.compile(r'\[(.*)\]:(\d+)')

    def dns_get_config(self) -> Dict[str, Union[Tuple[Ip6Addr, int], int, bool, str]]:
        """Get DNS client query config.
        """
        output = self.execute_command('dns config')
        config: Dict[str, Union[Tuple[Ip6Addr, int], int, bool, str]] = {}

        #
        # Example output:
        # > dns config
        # Server: [fd00:0:0:0:0:0:0:1]:1234
        # ResponseTimeout: 5000 ms
        # MaxTxAttempts: 2
        # RecursionDesired: no
        # ServiceMode: srv_txt_opt
        # Nat64Mode: allow
        # TransportProtocol: udp
        # Done
        #

        for line in output:
            k, v = line.split(': ')
            if k == 'Server':
                matched = re.match(OTCI._IPV6_SERVER_PORT_PATTERN, v)
                assert matched is not None
                ip, port = matched.groups()
                config['server'] = (Ip6Addr(ip), int(port))
            elif k == 'ResponseTimeout':
                config['response_timeout'] = int(v[:-3])
            elif k == 'MaxTxAttempts':
                config['max_tx_attempts'] = int(v)
            elif k == 'RecursionDesired':
                config['recursion_desired'] = (v == 'yes')
            elif k == 'ServiceMode':
                config['service_mode'] = v
            elif k == 'Nat64Mode':
                config['nat64_mode'] = (v == 'allow')
            elif k == 'TransportProtocol':
                config['transport_protocol'] = v
            else:
                logging.warning("dns config ignored: %s", line)

        return config

    @staticmethod
    def __add_with_default(l: list[str], var: Optional[Any], default: str = '0'):
        if var is not None:
            if isinstance(var, bool):
                l += ['1' if var else '0']
            else:
                l += [f'{var}']
        elif bool(l):
            l += [default]

    def dns_set_config(self,
                       server: Union[Tuple[Union[str, ipaddress.IPv6Address], int], Tuple[()]],
                       response_timeout: Optional[int] = None,
                       max_tx_attempts: Optional[int] = None,
                       recursion_desired: Optional[bool] = None,
                       service_mode: Optional[str] = None,
                       transport_protocol: Optional[str] = None):
        """Set DNS client query config."""
        # working backwards so we can set defaults when required
        cmd_parts: List[str] = []
        self.__add_with_default(cmd_parts, transport_protocol)
        self.__add_with_default(cmd_parts, service_mode)
        self.__add_with_default(cmd_parts, recursion_desired)
        self.__add_with_default(cmd_parts, max_tx_attempts)
        self.__add_with_default(cmd_parts, response_timeout)
        if server:
            self.__add_with_default(cmd_parts, server[1] or None)
            self.__add_with_default(cmd_parts, server[0] or '::', '::')
        else:
            self.__add_with_default(cmd_parts, None)
            self.__add_with_default(cmd_parts, None, '::')

        cmd = f'dns config {" ".join(cmd_parts[::-1])}'
        self.execute_command(cmd)

    def dns_get_compression(self) -> bool:
        """Get DNS compression mode."""
        return self.__parse_Enabled_or_Disabled(self.execute_command('dns compression'))

    def dns_enable_compression(self):
        """Enable DNS compression mode."""
        self.execute_command('dns compression enable')

    def dns_disable_compression(self):
        """Disable DNS compression mode."""
        self.execute_command('dns compression disable')

    def dns_browse(self,
                   service: str,
                   server: Optional[Union[Tuple[Union[str, ipaddress.IPv6Address], int], Tuple[()]]] = None,
                   response_timeout: Optional[int] = None,
                   max_tx_attempts: Optional[int] = None,
                   recursion_desired: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Browse DNS service instances."""

        cmd_parts: List[str] = []
        self.__add_with_default(cmd_parts, recursion_desired)
        self.__add_with_default(cmd_parts, max_tx_attempts)
        self.__add_with_default(cmd_parts, response_timeout)
        if server:
            self.__add_with_default(cmd_parts, server[1] or None)
            self.__add_with_default(cmd_parts, server[0] or '::', '::')
        else:
            self.__add_with_default(cmd_parts, None)
            self.__add_with_default(cmd_parts, None, '::')

        if cmd_parts:
            cmd = f'dns browse {service} {" ".join(cmd_parts)}'
        else:
            cmd = f'dns browse {service}'
        output = '\n'.join(self.execute_command(cmd, 30.0))

        result: List[Dict[str, Union[str, int, Ip6Addr, Dict[str, Union[bytes, bool]]]]] = []
        for ins, port, priority, weight, srv_ttl, hostname, address, aaaa_ttl, txt_data, txt_ttl in re.findall(
                r'(.*?)\s+Port:(\d+), Priority:(\d+), Weight:(\d+), TTL:(\d+)\s*Host:(\S+)\s+HostAddress:(\S+) ' +
                r'TTL:(\d+)\s+TXT:(\[.*?\]) TTL:(\d+)', output):
            result.append({
                'instance': ins,
                'service': service,
                'port': int(port),
                'priority': int(priority),
                'weight': int(weight),
                'host': hostname,
                'address': Ip6Addr(address),
                'txt': self.__parse_srp_server_service_txt(txt_data),
                'srv_ttl': int(srv_ttl),
                'txt_ttl': int(txt_ttl),
                'aaaa_ttl': int(aaaa_ttl),
            })

        return result

    def dns_resolve(self,
                    hostname: str,
                    ip_address: str = '',
                    ignore_result: bool = False) -> List[Dict[str, Union[Ip6Addr, int]]]:
        """Resolve a DNS host name."""
        cmd = 'dns resolve ' + ' '.join([x for x in [hostname, ip_address] if x])
        output = self.execute_command(cmd, 30.0, ignore_result=ignore_result)
        dns_resp = output[0]
        addrs = dns_resp.strip().split(' - ')[1].split(' ')
        ips = [Ip6Addr(item.strip()) for item in addrs[::2]]
        ttls = [int(item.split('TTL:')[1]) for item in addrs[1::2]]

        return [{
            'address': ip,
            'ttl': ttl,
        } for ip, ttl in zip(ips, ttls)]

    def dns_resolve_service(self,
                            instance: str,
                            service: str,
                            server: Optional[Tuple[Union[str, ipaddress.IPv6Address], int]] = None,
                            response_timeout: Optional[int] = None,
                            max_tx_attempts: Optional[int] = None,
                            recursion_desired: Optional[bool] = None,
                            ignore_result: bool = False) -> Dict[str, Any]:
        """Resolves a service instance."""

        cmd_parts: List[str] = []
        self.__add_with_default(cmd_parts, recursion_desired)
        self.__add_with_default(cmd_parts, max_tx_attempts)
        self.__add_with_default(cmd_parts, response_timeout)
        if server:
            self.__add_with_default(cmd_parts, server[1] or None)
            self.__add_with_default(cmd_parts, server[0] or '::')
        else:
            self.__add_with_default(cmd_parts, None)
            self.__add_with_default(cmd_parts, None, '::')

        instance = self.__escape_escapable(instance)

        if cmd_parts:
            cmd = f'dns service {instance} {service} {" ".join(cmd_parts[::-1])}'
        else:
            cmd = f'dns service {instance} {service}'

        output = self.execute_command(cmd, 30.0, ignore_result=ignore_result)

        m = re.match(
            r'.*Port:(\d+), Priority:(\d+), Weight:(\d+), TTL:(\d+)\s+Host:(.*?)\s+HostAddress:(\S+) ' +
            r'TTL:(\d+)\s+TXT:(\[.*?\]) TTL:(\d+)', '\t'.join(output))
        if m:
            port, priority, weight, srv_ttl, hostname, address, aaaa_ttl, txt_data, txt_ttl = m.groups()
            return {
                'instance': instance,
                'service': service,
                'port': int(port),
                'priority': int(priority),
                'weight': int(weight),
                'host': hostname,
                'address': Ip6Addr(address),
                'txt': self.__parse_srp_server_service_txt(txt_data),
                'srv_ttl': int(srv_ttl),
                'txt_ttl': int(txt_ttl),
                'aaaa_ttl': int(aaaa_ttl),
            }
        else:
            raise CommandError(cmd, output)

    def dns_resolve4(self,
                     hostname: str,
                     ip_address: str = '',
                     ignore_result: bool = False) -> List[Dict[str, Union[Ip4Addr, int]]]:
        """Resolve a DNS host name."""
        cmd = 'dns resolve4 ' + ' '.join([x for x in [hostname, ip_address] if x])
        output = self.execute_command(cmd, 30.0, ignore_result=ignore_result)
        dns_resp = output[0]
        addrs = dns_resp.strip().split(' - ')[1].split(' ')
        ips = [Ip4Addr(item.strip()) for item in addrs[::2]]
        ttls = [int(item.split('TTL:')[1]) for item in addrs[1::2]]

        return [{
            'address': ip,
            'ttl': ttl,
        } for ip, ttl in zip(ips, ttls)]

    #
    # SRP server & client utilities
    #

    def srp_server_get_state(self):
        """Get the SRP server state"""
        return self.__parse_str(self.execute_command('srp server state'))

    def srp_server_enable(self):
        """Enable SRP server."""
        self.execute_command('srp server enable')

    def srp_server_disable(self):
        """Disable SRP server."""
        self.execute_command('srp server disable')

    def srp_server_get_addressmode(self):
        """Get the SRP server address mode."""
        return self.__parse_str(self.execute_command(f'srp server addrmode'))

    def srp_server_set_addressmode(self, mode: Literal['unicast', 'anycast']):
        """Set the SRP server address mode."""
        self.execute_command(f'srp server addrmode {mode}')

    def srp_server_get_sequence_number(self) -> int:
        """Set SRP server sequence number."""
        return self.__parse_int(self.execute_command(f'srp server seqnum'))

    def srp_server_set_sequence_number(self, seq: int):
        """Set SRP server sequence number."""
        self.execute_command(f'srp server seqnum {seq}')

    def srp_server_get_domain(self) -> str:
        """Get the SRP server domain."""
        return self.__parse_str(self.execute_command('srp server domain'))

    def srp_server_set_domain(self, domain: str):
        """Set the SRP server domain."""
        self.execute_command(f'srp server domain {domain}')

    def srp_server_get_hosts(self) -> List[Dict[str, Any]]:
        """Get SRP server registered hosts."""
        return self.__parse_srp_server_hosts(self.execute_command('srp server host'))

    def srp_server_get_services(self) -> List[Dict[str, Any]]:
        """Get SRP server registered services."""
        output = self.execute_command('srp server service')
        return self.__parse_srp_server_services(output)

    def __parse_srp_server_hosts(self, output: List[str]) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        info: Optional[Dict[str, Any]] = None
        for line in output:
            if not line.startswith(' '):
                info = {'host': line}
                result.append(info)
            else:
                assert info is not None
                k, v = line.strip().split(': ')
                if k == 'deleted':
                    if v not in ('true', 'false'):
                        raise UnexpectedCommandOutput(output)

                    info['deleted'] = (v == 'true')

                elif k == 'addresses':
                    if not v.startswith('[') or not v.endswith(']'):
                        raise UnexpectedCommandOutput(output)

                    v = v[1:-1]
                    info['addresses'] = list(map(Ip6Addr, v.split(', ')))
                else:
                    raise UnexpectedCommandOutput(output)

        return result

    def __parse_srp_server_services(self, output: List[str]) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        info: Optional[Dict[str, Any]] = None
        for line in output:
            if not line.startswith(' '):
                info = {'instance': line}
                result.append(info)
            else:
                assert info is not None
                k, v = line.strip().split(': ')
                if k == 'deleted':
                    if v not in ('true', 'false'):
                        raise UnexpectedCommandOutput(output)

                    info['deleted'] = (v == 'true')

                elif k == 'addresses':
                    if not v.startswith('[') or not v.endswith(']'):
                        raise UnexpectedCommandOutput(output)

                    v = v[1:-1]
                    info['addresses'] = list(map(Ip6Addr, v.split(', ')))
                elif k == 'subtypes':
                    info[k] = list() if v == '(null)' else list(v.split(','))
                elif k in ('port', 'weight', 'priority', 'ttl', 'lease', 'key-lease'):
                    info[k] = int(v)
                elif k in ('host',):
                    info[k] = v
                elif k == 'TXT':
                    info['txt'] = self.__parse_srp_server_service_txt(v)
                else:
                    raise UnexpectedCommandOutput(output)

        return result

    def __parse_srp_server_service_txt(self, txt: str) -> Dict[str, Union[bytes, bool]]:
        # example value: [txt11=76616c3131, txt12=76616c3132]
        assert txt.startswith('[') and txt.endswith(']')
        txt_dict: Dict[str, Union[bytes, bool]] = {}
        for entry in txt[1:-1].split(', '):
            if not entry:
                continue

            equal_pos = entry.find('=')

            if equal_pos != -1:
                k, v = entry[:equal_pos], entry[equal_pos + 1:]
                txt_dict[k] = bytes(int(v[i:i + 2], 16) for i in range(0, len(v), 2))
            else:
                txt_dict[entry] = True

        return txt_dict

    def srp_server_get_lease(self) -> Tuple[int, ...]:
        """Get SRP server LEASE & KEY-LEASE range (in seconds)."""
        lines = self.execute_command('srp server lease')
        return tuple([int(line.split(':')[1].strip()) for line in lines])

    def srp_server_set_lease(self, min_lease: int, max_lease: int, min_key_lease: int, max_key_lease: int):
        """Configure SRP server LEASE & KEY-LEASE range (in seconds)."""
        self.execute_command(f'srp server lease {min_lease} {max_lease} {min_key_lease} {max_key_lease}')

    def srp_client_get_state(self) -> bool:
        """Get SRP client state."""
        return self.__parse_Enabled_or_Disabled(self.execute_command('srp client state'))

    def srp_client_start(self, server_ip: Union[str, ipaddress.IPv6Address], server_port: int):
        """Start SRP client."""
        self.execute_command(f'srp client start {str(server_ip)} {server_port}')

    def srp_client_stop(self):
        """Stop SRP client."""
        self.execute_command('srp client stop')

    def srp_client_get_autostart(self) -> bool:
        """Get SRP client autostart mode."""
        return self.__parse_Enabled_or_Disabled(self.execute_command('srp client autostart'))

    def srp_client_enable_autostart(self):
        """Enable SRP client autostart mode."""
        self.execute_command('srp client autostart enable')

    def srp_client_disable_autostart(self):
        """Disable SRP client autostart mode."""
        self.execute_command('srp client autostart disable')

    def srp_client_get_callback(self) -> bool:
        """Get SRP client callback mode."""
        return self.__parse_Enabled_or_Disabled(self.execute_command('srp client callback'))

    def srp_client_enable_callback(self):
        """Enable SRP client callback mode."""
        self.execute_command('srp client callback enable')

    def srp_client_disable_callback(self):
        """Disable SRP client callback mode."""
        self.execute_command('srp client callback disable')

    def srp_client_set_host_name(self, name: str):
        """Set SRP client host name."""
        self.execute_command(f'srp client host name {name}')

    def srp_client_get_host(self) -> Dict[str, Union[str, List[Ip6Addr]]]:
        """Get SRP client host."""
        output = self.__parse_str(self.execute_command('srp client host'))
        return self.__parse_srp_client_host(output)

    _SRP_CLIENT_HOST_PATTERN = re.compile(r'name:("(.*)"|(\(null\))), state:(\S+), addrs:\[(.*)\]')

    def __parse_srp_client_host(self, line: str) -> Dict[str, Union[str, List[Ip6Addr]]]:
        m = re.match(OTCI._SRP_CLIENT_HOST_PATTERN, line)
        if not m:
            raise UnexpectedCommandOutput([line])

        _, host, _, state, addrs = m.groups()
        return {
            'host': host or '',
            'state': state,
            'addresses': [Ip6Addr(ip) for ip in addrs.split(', ')] if addrs else [],
        }

    def srp_client_get_host_name(self) -> str:
        """Get SRP client host name."""
        name = self.__parse_str(self.execute_command('srp client host name'))
        return name if name != '(null)' else ''

    def srp_client_get_host_addresses(self) -> List[Ip6Addr]:
        """Get SRP client host addresses."""
        return self.__parse_ip6addr_list(self.execute_command('srp client host address'))

    def srp_client_set_host_addresses(self, *addrs: Union[str, ipaddress.IPv6Address]):
        """Set SRP client host addresses."""
        self.execute_command(f'srp client host address {" ".join(map(str, addrs))}')

    def srp_client_get_host_state(self):
        """Get SRP client host state."""
        return self.__parse_str(self.execute_command('srp client host state'))

    def srp_client_remove_host(self, remove_key_lease: bool = False):
        """Remove SRP client host."""
        cmd = 'srp client host remove'
        if remove_key_lease:
            cmd += ' 1'

        self.execute_command(cmd)

    def srp_client_clear_host(self):
        """Clear SRP client host without notifying the SRP server."""
        self.execute_command('srp client host clear')

    def srp_client_get_services(self) -> List[Dict[str, Union[str, int]]]:
        """Get SRP client services."""
        output = self.execute_command('srp client service')
        return [self.__parse_srp_client_service(line) for line in output]

    _SRP_CLIENT_SERVICE_PATTERN = re.compile(
        r'instance:"(.*)", name:"(.*)", state:(\S+), port:(\d+), priority:(\d+), weight:(\d+)')

    def __parse_srp_client_service(self, line: str) -> Dict[str, Union[str, int]]:
        # e.g. instance:"ins2", name:"_meshcop._udp", state:ToAdd, port:2000, priority:2, weight:2
        m = OTCI._SRP_CLIENT_SERVICE_PATTERN.match(line)
        if m is None:
            raise UnexpectedCommandOutput([line])

        instance, service, state, port, priority, weight = m.groups()
        port, priority, weight = int(port), int(priority), int(weight)
        return {
            'instance': instance,
            'service': service,
            'state': state,
            'port': port,
            'priority': priority,
            'weight': weight,
        }

    def srp_client_add_service(self,
                               instance: str,
                               service: str,
                               port: int,
                               priority: int = 0,
                               weight: int = 0,
                               txt: Optional[Dict[str, Union[str, bytes, bool]]] = None):
        instance = self.__escape_escapable(instance)
        cmd = f'srp client service add {instance} {service} {port} {priority} {weight}'
        if txt:
            cmd += f' {self.__txt_to_hex(txt)}'
        self.execute_command(cmd)

    def srp_client_remove_service(self, instance: str, service: str):
        """Remove a service from SRP client."""
        self.execute_command(f'srp client service remove {instance} {service}')

    def srp_client_clear_service(self, instance: str, service: str):
        """Remove a service from SRP client without notifying the SRP server."""
        self.execute_command(f'srp client service clear {instance} {service}')

    def srp_client_get_key_lease_interval(self) -> int:
        """Get SRP client key lease interval (in seconds)."""
        return self.__parse_int(self.execute_command('srp client keyleaseinterval'))

    def srp_client_set_key_lease_interval(self, interval: int):
        """Set SRP client key lease interval (in seconds)."""
        self.execute_command(f'srp client keyleaseinterval {interval}')

    def srp_client_get_lease_interval(self) -> int:
        """Get SRP client lease interval (in seconds)."""
        return self.__parse_int(self.execute_command('srp client leaseinterval'))

    def srp_client_set_lease_interval(self, interval: int):
        """Set SRP client lease interval (in seconds)."""
        self.execute_command(f'srp client leaseinterval {interval}')

    def srp_client_get_server(self) -> Tuple[Ip6Addr, int]:
        """Get the SRP server (IP, port)."""
        result = self.__parse_str(self.execute_command('srp client server'))
        matched = re.match(OTCI._IPV6_SERVER_PORT_PATTERN, result)
        assert matched
        ip, port = matched.groups()
        return Ip6Addr(ip), int(port)

    def srp_client_get_service_key(self) -> bool:
        """Get SRP client "service key record inclusion" mode."""
        return self.__parse_Enabled_or_Disabled(self.execute_command('srp client service key'))

    def srp_client_enable_service_key(self):
        """Enable SRP client "service key record inclusion" mode."""
        self.execute_command('srp client service key enable')

    def srp_client_disable_service_key(self):
        """Disable SRP client "service key record inclusion" mode."""
        self.execute_command('srp client service key disable')

    def __split_table_row(self, row: str) -> List[str]:
        if not (row.startswith('|') and row.endswith('|')):
            raise ValueError(row)

        fields = row.split('|')
        fields = [x.strip() for x in fields[1:-1]]
        return fields

    def __get_table_col(self, col_name: str, headers: List[str], fields: List[str]) -> str:
        return fields[headers.index(col_name)]

    def get_child_list(self) -> List[ChildId]:
        """Get attached Child IDs."""
        line = self.__parse_str(self.execute_command('child list'))
        return [ChildId(id) for id in line.strip().split()]

    def get_child_info(self, child: Union[ChildId, Rloc16]) -> Dict[str, Union[int, str]]:
        output = self.execute_command(f'child {child}')

        info: Dict[str, Union[int, str]] = {}

        for line in output:
            k, v = line.split(': ')
            if k == 'Child ID':
                info['id'] = int(v)
            elif k == 'Rloc':
                info['rloc16'] = int(v, 16)
            elif k == 'Ext Addr':
                info['extaddr'] = v
            elif k == 'Mode':
                info['mode'] = DeviceMode(v)
            elif k == 'Net Data':
                info['c_vn'] = int(v)
            elif k == 'Timeout':
                info['timeout'] = int(v)
            elif k == 'Age':
                info['age'] = int(v)
            elif k == 'Link Quality In':
                info['lq_in'] = int(v)
            elif k == 'RSSI':
                info['rssi'] = int(v)
            else:
                self.log('warning', "Child info %s: %s ignored", k, v)

        return info

    def get_child_ipaddrs(self) -> Dict[Rloc16, List[Ip6Addr]]:
        """Get the list of IP addresses stored for MTD children.

        Note: Each MTD child might has multiple IP addresses.
        """
        output = self.execute_command('childip')

        ipaddrs: Dict[Rloc16, List[Ip6Addr]] = {}

        for line in output:
            rloc16, ip = line.split(': ')
            rloc16 = Rloc16(rloc16, 16)
            ipaddrs.setdefault(rloc16, []).append(Ip6Addr(ip.strip()))

        return ipaddrs

    #
    # Child configurations
    #

    def get_max_children(self) -> int:
        """Get the Thread maximum number of allowed children."""
        return self.__parse_int(self.execute_command('childmax'))

    def set_max_children(self, val: int):
        """Set the Thread maximum number of allowed children."""
        self.execute_command(f'childmax {val}')

    def get_child_ip_max(self) -> int:
        """Get the maximum number of IP addresses that each MTD child may register with this device as parent."""
        return self.__parse_int(self.execute_command('childip max'))

    def set_child_ip_max(self, val: int):
        """Get the maximum number of IP addresses that each MTD child may register with this device as parent."""
        self.execute_command(f'childip max {val}')

    def get_child_timeout(self) -> int:
        """Get the Thread Child Timeout value."""
        return self.__parse_int(self.execute_command('childtimeout'))

    def set_child_timeout(self, timeout: int):
        """Set the Thread Child Timeout value."""
        self.execute_command('childtimeout %d' % timeout)

    def get_child_supervision_interval(self) -> int:
        """Get the Child Supervision Check Timeout value."""
        return self.__parse_int(self.execute_command('childsupervision interval'))

    def set_child_supervision_interval(self, val: int):
        """Set the Child Supervision Interval value.
        This command can only be used with FTD devices.
        """
        self.execute_command(f'childsupervision interval {val}')

    def get_child_supervision_check_timeout(self) -> int:
        """Get the Child Supervision Check Timeout value."""
        return self.__parse_int(self.execute_command('childsupervision checktimeout'))

    def set_child_supervision_check_timeout(self, val: int):
        """Set the Child Supervision Check Timeout value."""
        self.execute_command(f'childsupervision checktimeout {val}')

    #
    # Neighbor management
    #

    def get_neighbor_list(self) -> List[Rloc16]:
        """Get a list of RLOC16 of neighbors"""
        line = self.__parse_str(self.execute_command('neighbor list')).strip()
        return [Rloc16(id, 16) for id in line.split()]

    def get_neighbor_table(self) -> Dict[Rloc16, Dict[str, Any]]:
        output = self.execute_command('neighbor table')
        if len(output) < 2:
            raise UnexpectedCommandOutput(output)

        #
        # Example output:
        #
        # | Role | RLOC16 | Age | Avg RSSI | Last RSSI |R|D|N| Extended MAC     |
        # +------+--------+-----+----------+-----------+-+-+-+------------------+
        # |   C  | 0xcc01 |  96 |      -46 |       -46 |1|1|1| 1eb9ba8a6522636b |
        # |   R  | 0xc800 |   2 |      -29 |       -29 |1|1|1| 9a91556102c39ddb |
        # |   R  | 0xf000 |   3 |      -28 |       -28 |1|1|1| 0ad7ed6beaa6016d |
        # Done
        #

        headers = self.__split_table_row(output[0])

        table: Dict[Rloc16, Dict[str, Any]] = {}
        for line in output[2:]:
            line = line.strip()
            if not line:
                continue

            fields = self.__split_table_row(line)

            def col(col_name: str) -> str:
                return self.__get_table_col(col_name, headers, fields)

            role = col('Role')
            is_router = role == 'R'
            r, d, n = int(col('R')), int(col('D')), int(col('N'))
            mode = DeviceMode(f'{"r" if r else ""}{"d" if d else ""}{"n" if n else ""}')

            rloc16 = Rloc16(col('RLOC16'), 16)

            table[rloc16] = {
                'is_router': is_router,
                'rloc16': rloc16,
                'age': int(col('Age')),
                'avg_rssi': int(col('Avg RSSI')),
                'last_rssi': int(col('Last RSSI')),
                'mode': mode,
                'extaddr': col('Extended MAC'),
            }

        return table

    #
    # SED/SSED configuration
    #

    def get_poll_period(self) -> int:
        """Get the customized data poll period of sleepy end device (milliseconds).
        Only for Reference Device."""
        return self.__parse_int(self.execute_command('pollperiod'))

    def set_poll_period(self, poll_period: int):
        """Set the customized data poll period (in milliseconds) for sleepy end device.

        Only for Reference Device."""
        self.execute_command(f'pollperiod {poll_period}')

    # TODO: csl

    def get_csl_period(self) -> int:
        """Get the CSL period

        Returns:
            int: csl period [us] (multiple of 160us)
        """
        return self.__parse_int(self.execute_command("csl period"))

    def set_csl_period(self, period: int):
        """Set the CSL timeout

        Args:
            period (int): csl period [us] in multiples of 160us
        """
        self.execute_command(f"csl period {period}")

    def set_csl_timeout(self, timeout: int):
        """Set the CSL timeout

        Args:
            timeout (int): csl timeout [s]
        """
        self.execute_command(f"csl timeout {timeout}")

    _CSL_PERIOD_PATTERN = re.compile(r'(\d+)us')
    _CSL_TIMEOUT_PATTERN = re.compile(r'(\d+)s')

    def get_csl_config(self) -> Dict[str, int]:
        """Get the CSL configuration."""
        output = self.execute_command('csl')

        cfg: Dict[str, int] = {}
        for line in output:
            k, v = line.split(': ')
            if k == 'channel':
                cfg[k] = int(v)
            elif k == 'timeout':
                matched = OTCI._CSL_TIMEOUT_PATTERN.match(v)
                assert matched is not None
                cfg[k] = int(matched.group(1))
            elif k == 'period':
                matched = OTCI._CSL_PERIOD_PATTERN.match(v)
                assert matched is not None
                cfg[k] = int(matched.group(1))
            else:
                logging.warning("Ignore unknown CSL parameter: %s: %s", k, v)

        return cfg

    def config_csl(self, channel: Optional[int] = None, period: Optional[int] = None, timeout: Optional[int] = None):
        """Configure CSL parameters.

        :param channel: Set CSL channel.
        :param period: Set CSL period in usec. Disable CSL by setting this parameter to 0.
        :param timeout: Set the CSL timeout in seconds.
        """

        if channel is None and period is None and timeout is None:
            raise InvalidArgumentsError("Please specify at least 1 parameter to configure.")

        if channel is not None:
            self.execute_command(f'csl channel {channel}')

        if period is not None:
            self.execute_command(f'csl period {period}')

        if timeout is not None:
            self.execute_command(f'csl timeout {timeout}')

    #
    # Leader utilities
    #

    def get_context_id_reuse_delay(self) -> int:
        """Get the CONTEXT_ID_REUSE_DELAY value."""
        return self.__parse_int(self.execute_command('contextreusedelay'))

    def set_context_id_reuse_delay(self, val: int):
        """Set the CONTEXT_ID_REUSE_DELAY value."""
        self.execute_command(f'contextreusedelay {val}')

    def release_router_id(self, routerid: int):
        """Release a Router ID that has been allocated by the device in the Leader role."""
        self.execute_command(f'releaserouterid {routerid}')

    # Time Sync utilities
    # TODO: networktime
    # TODO: networktime <timesyncperiod> <xtalthreshold>

    def get_minimal_delay_timer(self) -> int:
        """Get the minimal delay timer (in seconds).

        Returns:
            int: minimal delay timer in seconds
        """
        return self.__parse_int(self.execute_command('delaytimermin'))

    def set_minimal_delay_timer(self, timer: int):
        """Set the minimal delay timer (in seconds)."""
        return self.execute_command(f'delaytimermin {timer}')

    #
    # Commissioner operations
    #

    def commissioner_start(self):
        """Start the Commissioner role."""
        self.execute_command('commissioner start')

    def commissioner_stop(self):
        """Stop the Commissioner role."""
        self.execute_command('commissioner stop')

    def get_commissioner_state(self) -> str:
        """Get current Commissioner state (active or petitioning or disabled)."""
        return self.__parse_str(self.execute_command('commissioner state'))

    def get_commissioner_session_id(self) -> int:
        """Get current commissioner session id."""
        return self.__parse_int(self.execute_command('commissioner sessionid'))

    def commissioner_add_joiner(self,
                                pskd: str,
                                eui64: Optional[str] = None,
                                discerner: Optional[str] = None,
                                timeout: Optional[int] = None):
        """Add a Joiner entry.

        :param pskd: Pre-Shared Key for the Joiner.
        :param eui64: The IEEE EUI-64 of the Joiner or '*' to match any Joiner
        :param discerner: The Joiner discerner in format number/length.
        :param timeout: Joiner timeout in seconds.
        """
        if (eui64 is not None) == (discerner is not None):
            raise InvalidArgumentsError("Please specify eui64 or discerner, but not both.")

        if eui64 is not None and eui64 != '*':
            self.__validate_extaddr(eui64)

        cmd = f'commissioner joiner add {eui64 or discerner} {pskd}'

        if timeout is not None:
            cmd += f' {timeout}'

        self.execute_command(cmd)

    def commissioner_remove_joiner(self, eui64: Optional[str] = None, discerner: Optional[str] = None):
        if (eui64 is not None) == (discerner is not None):
            raise InvalidArgumentsError("Please specify eui64 or discerner, but not both.")

        if eui64 is not None and eui64 != '*':
            self.__validate_extaddr(eui64)

        self.execute_command(f'commissioner joiner remove {eui64 or discerner}')

    def set_commissioner_provisioning_url(self, url: str):
        self.execute_command(f'commissioner provisioningurl {url}')

    def commissioner_announce(self, channel_mask: int, count: int, period: int, destination: str | Ip6Addr):
        """Send an MLE Discovery Request to the specified destination."""
        self.execute_command(f'commissioner announce {channel_mask} {count} {period} {destination}')

    def commissioner_energy_scan(self, channel_mask: int, count: int, period: int, duration: int,
                                 destination: str | Ip6Addr) -> Dict[int, List[int]]:
        """Perform an energy scan on the specified channels."""
        ch_count = len(list(bits_set(channel_mask)))
        self.execute_command(f'commissioner energy {channel_mask} {count} {period} {duration} {destination}')
        output = self.__otcmd.wait(ch_count * count * (period + duration + 999) / 1000 + 1)

        if len(output) > 1:
            raise UnexpectedCommandOutput(output)

        _mask, _energies = output[0].split(": ")[1].split(" ", 1)
        channels = [b for b in bits_set(int(_mask, 16))]
        energies = [int(e) for e in _energies.split(" ")]
        return {ch: energies[idx::len(channels)] for (idx, ch) in enumerate(channels)}

    def commissioner_mgmt_get(self,
                              named_tlvs: Optional[Tuple[str, ...]] = None,
                              hex_tlvs: Optional[Tuple[int, ...]] = None):
        """Send a MGMT_GET request."""
        _cmd: List[str] = ['commissioner', 'mgmtget']

        if named_tlvs:
            _cmd += named_tlvs

        if hex_tlvs:
            _cmd += [self.__detect_binary_cmd(), "".join(f"{x:02x}" for x in hex_tlvs)]

        self.execute_command(' '.join(_cmd))

    def commissioner_mgmt_set(self,
                              locator: Optional[str] = None,
                              session_id: Optional[int] = None,
                              steering_data: Optional[str] = None,
                              joiner_udp_port: Optional[int] = None,
                              tlvs: Optional[str] = None):
        """Send a MGMT_SET request."""
        _names = ['locator', 'sessionid', 'steeringdata', 'joinerudpport', self.__detect_binary_cmd()]
        _tlvs: List[Union[int, str, None]] = [locator, session_id, steering_data, joiner_udp_port, tlvs]
        _cmd = [x for x in zip(_names, _tlvs) if x[1] is not None]

        if not _cmd:
            # Nothing to do
            return

        self.execute_command(f'commissioner mgmtset {" ".join([f"{k} {v}" for k, v in _cmd])}')

    def commissioner_panid_query(self, panid: int, channel_mask: int, destination: str | Ip6Addr) -> List[int]:
        """Perform a PAN ID query on the specified channels."""
        self.execute_command(f'commissioner panid {panid} {channel_mask} {destination}')
        output = self.__otcmd.wait(len(list(bits_set(channel_mask))))
        if output:
            masks = [int(line.split(": ")[1].split(", ", 1)[1], 16) for line in output]
            conflict_mask = functools.reduce(lambda x, y: x | y, masks)
            return [b for b in bits_set(conflict_mask)]
        else:
            return []

    #
    # Joiner operations
    #
    def joiner_start(self, psk: str, provisioning_url: Optional[str] = None):
        """Start the Joiner."""
        cmd = f'joiner start {psk}'
        if provisioning_url is not None:
            cmd += f' {provisioning_url}'

        self.execute_command(cmd)

    def joiner_stop(self):
        """Stop the Joiner role."""
        self.execute_command('joiner stop')

    def get_joiner_id(self) -> str:
        """Get the Joiner ID."""
        return self.__parse_joiner_id(self.execute_command('joiner id'))

    def get_joiner_port(self) -> int:
        """Get the Joiner port."""
        return self.__parse_int(self.execute_command('joinerport'))

    def set_joiner_port(self, port: int):
        """Set the Joiner port."""
        self.execute_command(f'joinerport {port}')

    # TODO: joiner discerner

    #
    # Network Data utilities
    #
    def get_mesh_local_prefix(self) -> Ip6Prefix:
        """Set the Mesh Local Prefix."""
        return self.__parse_prefix(self.execute_command('prefix meshlocal'))

    def set_mesh_local_prefix(self, prefix: str):
        """Set the Mesh Local Prefix."""
        self.execute_command(f'prefix meshlocal {prefix}')

    def get_local_prefixes(self) -> List[Tuple[Ip6Prefix, str, str, Rloc16]]:
        """Get prefixes from local Network Data."""
        output = self.execute_command('prefix')
        return self.__parse_prefixes(output)

    def __parse_prefix(self, output: List[str]) -> Ip6Prefix:
        if len(output) != 1:
            raise UnexpectedCommandOutput(output)
        try:
            return Ip6Prefix(str(ipaddress.IPv6Network(output[0])))
        except ValueError:
            raise UnexpectedCommandOutput(output)

    def __parse_prefixes(self, output: List[str]) -> List[Tuple[Ip6Prefix, str, str, Rloc16]]:
        prefixes: List[Tuple[Ip6Prefix, str, str, Rloc16]] = []

        for line in output:
            if line.startswith('- '):
                line = line[2:]

            prefix, flags, prf, rloc16 = line.split()[:4]
            prefixes.append((self.__parse_prefix([prefix]), flags, prf, Rloc16(rloc16, 16)))

        return prefixes

    def add_prefix(self, prefix: str, flags: str = 'paosr', prf: str = 'med'):
        """Add a valid prefix to the Network Data."""
        self.execute_command(f'prefix add {prefix} {flags} {prf}')

    def remove_prefix(self, prefix: str):
        """Invalidate a prefix in the Network Data."""
        self.execute_command(f'prefix remove {prefix}')

    def register_network_data(self):
        self.execute_command('netdata register')

    def network_data_public_prefix(self, prefix: str, flags: str = 'paos', preference: str = 'med'):
        self.execute_command(f'netdata publish prefix {prefix} {flags} {preference}')

    def network_data_unpublish_prefix(self, prefix: str):
        self.execute_command(f'netdata unpublish {prefix}')

    def network_data_unpublish_dnssrp(self):
        self.execute_command('netdata unpublish dnssrp')

    def get_network_data(self) -> Dict[str, List[Any]]:
        output = self.execute_command('netdata show')

        netdata: Dict[str, List[Any]] = {}
        if output.pop(0) != 'Prefixes:':
            raise UnexpectedCommandOutput(output)

        prefixes_output: List[str] = []
        while True:
            line = output.pop(0)
            if line == 'Routes:':
                break
            else:
                prefixes_output.append(line)

        netdata['prefixes'] = self.__parse_prefixes(prefixes_output)

        routes_output: List[str] = []
        while True:
            line = output.pop(0)
            if line == 'Services:':
                break
            else:
                routes_output.append(line)

        netdata['routes'] = self.__parse_routes(routes_output)

        services_output: List[str] = []
        while True:
            line = output.pop(0)
            if line == 'Contexts:':
                break
            else:
                services_output.append(line)

        netdata['services'] = self.__parse_services(services_output)

        return netdata

    def get_prefixes(self) -> List[Tuple[Ip6Prefix, str, str, Rloc16]]:
        """Get network prefixes from Thread Network Data."""
        network_data = self.get_network_data()
        return network_data['prefixes']

    def get_routes(self) -> List[Tuple[str, bool, str, Rloc16]]:
        """Get routes from Thread Network Data."""
        network_data = self.get_network_data()
        return network_data['routes']

    def get_services(self) -> List[Tuple[int, bytes, bytes, bool, Rloc16]]:
        """Get services from Thread Network Data"""
        network_data = self.get_network_data()
        return network_data['services']

    def __parse_services(self, output: List[str]) -> List[Tuple[int, bytes, bytes, bool, Rloc16]]:
        services: List[Tuple[int, bytes, bytes, bool, Rloc16]] = []
        for line in output:
            line = line.split()

            enterprise_number, service_data, server_data = line[:3]
            if line[3] == 's':
                stable, rloc16 = True, line[4]
            else:
                stable, rloc16 = False, line[3]

            enterprise_number = int(enterprise_number)
            service_data = self.__hex_to_bytes(service_data)
            server_data = self.__hex_to_bytes(server_data)
            rloc16 = Rloc16(rloc16, 16)

            services.append((enterprise_number, service_data, server_data, stable, rloc16))

        return services

    def get_network_data_bytes(self) -> bytes:
        """Get the raw Network Data."""
        hexstr = self.__parse_str(self.execute_command(f'netdata show {self.__detect_binary_cmd()}'))
        return bytes(int(hexstr[i:i + 2], 16) for i in range(0, len(hexstr), 2))

    def get_local_routes(self) -> List[Tuple[str, bool, str, Rloc16]]:
        """Get routes from local Network Data."""
        return self.__parse_routes(self.execute_command('route'))

    def __parse_routes(self, output: List[str]) -> List[Tuple[str, bool, str, Rloc16]]:
        routes: List[Tuple[str, bool, str, Rloc16]] = []
        for line in output:
            line = line.split()
            if len(line) == 4:
                prefix, flags, prf, rloc16 = line
                stable = 's' in flags
            else:
                prefix, prf, rloc16 = line
                stable = False

            rloc16 = Rloc16(rloc16, 16)
            routes.append((prefix, stable, prf, rloc16))

        return routes

    def add_route(self, prefix: str, stable: bool = True, prf: str = 'med'):
        """Add a valid external route to the Network Data."""
        cmd = f'route add {prefix}'
        if stable:
            cmd += ' s'

        cmd += f' {prf}'
        self.execute_command(cmd)

    def remove_route(self, prefix: str):
        """Invalidate a external route in the Network Data."""
        self.execute_command(f'route remove {prefix}')

    def add_service(self, enterprise_number: int, service_data: Union[str, bytes], server_data: Union[str, bytes]):
        """Add service to the Network Data.

        enterpriseNumber: IANA enterprise number
        serviceData: hex-encoded binary service data
        serverData: hex-encoded binary server data
        """
        service_data = self.__validate_hex_or_bytes(service_data)
        server_data = self.__validate_hex_or_bytes(server_data)
        self.execute_command(f'service add {enterprise_number} {service_data} {server_data}')

    def remove_service(self, enterprise_number: int, service_data: Union[str, bytes]):
        """Remove service from Network Data.

        enterpriseNumber: IANA enterprise number
        serviceData: hex-encoded binary service data
        """
        service_data = self.__validate_hex_or_bytes(service_data)
        self.execute_command(f'service remove {enterprise_number} {service_data}')

    #
    # Dataset management
    #

    def dataset_init_buffer(self, get_active_dataset: bool = False, get_pending_dataset: bool = False):
        """Initialize operational dataset buffer."""
        if get_active_dataset and get_pending_dataset:
            raise InvalidArgumentsError("Can not specify both `get_active_dataset` and `get_pending_dataset`.")

        if get_active_dataset:
            self.execute_command('dataset init active')
        elif get_pending_dataset:
            self.execute_command('dataset init pending')
        else:
            self.execute_command('dataset init new')

    def dataset_commit_buffer(self, dataset: str):
        if dataset in ('active', 'pending'):
            cmd = f'dataset commit {dataset}'
        else:
            raise InvalidArgumentsError(f'Unknown dataset: {dataset}')

        self.execute_command(cmd)

    def dataset_clear_buffer(self):
        """Reset operational dataset buffer."""
        self.execute_command('dataset clear')

    def get_dataset(self, dataset: str = 'buffer'):
        if dataset in ('active', 'pending'):
            cmd = f'dataset {dataset}'
        elif dataset == 'buffer':
            cmd = 'dataset'
        else:
            raise InvalidArgumentsError(f'Unknown dataset: {dataset}')

        output = self.execute_command(cmd)
        return self.__parse_dataset(output)

    def __parse_dataset(self, output: List[str]) -> Dict[str, Any]:
        # Example output:
        #
        # Active Timestamp: 1
        # Channel: 22
        # Wake-up Channel: 11
        # Channel Mask: 0x07fff800
        # Ext PAN ID: 5c93ae980ff22d35
        # Mesh Local Prefix: fdc7:55fe:6363:bd01::/64
        # Network Key: d1a8348d59fb1fac1d6c4f95007d487a
        # Network Name: OpenThread-7caa
        # PAN ID: 0x7caa
        # PSKc: 167d89fd169e439ca0b8266de248090f
        # Security Policy: 672 onrc 0

        dataset: Dict[str, Any] = {}

        for line in output:
            line = line.split(': ')
            key, val = line[0], ': '.join(line[1:])

            if key == 'Active Timestamp':
                dataset['active_timestamp'] = int(val)
            elif key == 'Channel':
                dataset['channel'] = int(val)
            elif key == 'Wake-up Channel':
                dataset['wakeupchannel'] = int(val)
            elif key == 'Channel Mask':
                dataset['channel_mask'] = int(val, 16)
            elif key == 'Ext PAN ID':
                dataset['extpanid'] = val
            elif key == 'Mesh Local Prefix':
                dataset['mesh_local_prefix'] = val
            elif key in ('Network Key', 'Master Key'):
                dataset['networkkey'] = val
            elif key == 'Network Name':
                dataset['network_name'] = val
            elif key == 'PAN ID':
                dataset['panid'] = int(val, 16)
            elif key == 'PSKc':
                dataset['pskc'] = val
            elif key == 'Security Policy':
                rotation_time, flags, _ = val.split(' ')  # Third value `version_threshold` is unused
                rotation_time = int(rotation_time)
                dataset['security_policy'] = SecurityPolicy(rotation_time, flags)
            else:
                raise UnexpectedCommandOutput(output)

        return dataset

    def get_dataset_bytes(self, dataset: str) -> bytes:
        if dataset in ('active', 'pending'):
            cmd = f'dataset {dataset} {self.__detect_binary_cmd()}'
        else:
            raise InvalidArgumentsError(f'Unknown dataset: {dataset}')

        hexstr = self.__parse_str(self.execute_command(cmd))
        return self.__hex_to_bytes(hexstr)

    def set_dataset_bytes(self, dataset: str, data: bytes) -> None:
        if dataset in ('active', 'pending'):
            cmd = f'dataset set {dataset} {self.__bytes_to_hex(data)}'
        else:
            raise InvalidArgumentsError(f'Unknown dataset: {dataset}')

        self.execute_command(cmd)

    def get_dataset_tlvs_bytes(self) -> bytes:
        """Gets bytes of the Operational Dataset TLVs"""
        hexstr = self.__parse_str(self.execute_command('dataset tlvs'))
        return self.__hex_to_bytes(hexstr)

    def dataset_set_buffer(self,
                           active_timestamp: Optional[int] = None,
                           channel: Optional[int] = None,
                           wakeupchannel: Optional[int] = None,
                           channel_mask: Optional[int] = None,
                           extpanid: Optional[str] = None,
                           mesh_local_prefix: Optional[str] = None,
                           network_key: Optional[str] = None,
                           network_name: Optional[str] = None,
                           panid: Optional[int] = None,
                           pskc: Optional[str] = None,
                           security_policy: Optional[tuple[int, str]] = None,
                           pending_timestamp: Optional[int] = None):
        if active_timestamp is not None:
            self.execute_command(f'dataset activetimestamp {active_timestamp}')

        if channel is not None:
            self.execute_command(f'dataset channel {channel}')

        if wakeupchannel is not None:
            self.execute_command(f'dataset wakeupchannel {wakeupchannel}')

        if channel_mask is not None:
            self.execute_command(f'dataset channelmask {channel_mask:#08x}')

        if extpanid is not None:
            self.execute_command(f'dataset extpanid {extpanid}')

        if mesh_local_prefix is not None:
            self.execute_command(f'dataset meshlocalprefix {mesh_local_prefix}')

        if network_key is not None:
            nwk_cmd = self.__detect_networkkey_cmd()
            self.execute_command(f'dataset {nwk_cmd} {network_key}')

        if network_name is not None:
            self.execute_command(f'dataset networkname {self.__escape_escapable(network_name)}')

        if panid is not None:
            self.execute_command(f'dataset panid {panid:#04x}')

        if pskc is not None:
            self.execute_command(f'dataset pskc {pskc}')

        if security_policy is not None:
            rotation_time, flags = security_policy
            self.execute_command(f'dataset securitypolicy {rotation_time} {flags}')

        if pending_timestamp is not None:
            self.execute_command(f'dataset pendingtimestamp {pending_timestamp}')

    def dataset_mgmt_get_command(self,
                                 dataset: str,
                                 address: Optional[str | Ip6Addr] = None,
                                 named_tlvs: Optional[List[Tuple[str, str]]] = None,
                                 hex_tlvs: Optional[Tuple[int, ...]] = None):
        _cmd: List[str] = ['dataset', 'mgmtgetcommand', dataset]

        if address is not None:
            _cmd += ['address', str(address)]

        if named_tlvs is not None:
            # flatten the list of tuples
            _cmd += [item for sublist in named_tlvs for item in sublist]

        if hex_tlvs is not None:
            _cmd += [self.__detect_binary_cmd(), ''.join([f'{tlv:02x}' for tlv in hex_tlvs])]

        self.execute_command(' '.join(_cmd))

    def dataset_mgmt_set_command(self,
                                 dataset: str,
                                 named_tlvs: Optional[List[Tuple[str, Any]]] = None,
                                 hex_tlvs: Optional[str] = None):
        _cmd = ['dataset', 'mgmtsetcommand', dataset]

        if named_tlvs is not None:
            _cmd += list(sum(named_tlvs, ()))

        if hex_tlvs is not None:
            _cmd += [self.__detect_binary_cmd(), hex_tlvs]

        self.execute_command(' '.join(_cmd))

    # TODO: dataset set <active|pending> <dataset>

    #
    # Allowlist management
    #

    def enable_allowlist(self):
        self.execute_command(f'macfilter addr {self.__detect_allowlist_cmd()}')

    def disable_allowlist(self):
        self.execute_command('macfilter addr disable')

    def add_allowlist(self, addr: str, rssi: Optional[int] = None):
        cmd = f'macfilter addr add {addr}'

        if rssi is not None:
            cmd += f' {rssi}'

        self.execute_command(cmd)

    def remove_allowlist(self, addr: str):
        self.execute_command(f'macfilter addr remove {addr}')

    def clear_allowlist(self):
        self.execute_command('macfilter addr clear')

    def set_allowlist(self, allowlist: Optional[Collection[Union[str, Tuple[str, int]]]]):
        """Add addresses to the allowlist"""
        self.clear_allowlist()

        if allowlist is None:
            self.disable_allowlist()
        else:
            self.enable_allowlist()
            for item in allowlist:
                if isinstance(item, str):
                    self.add_allowlist(item)
                else:
                    addr, rssi = item[0], item[1]
                    self.add_allowlist(addr, rssi)

    def enable_denylist(self):
        self.execute_command(f'macfilter addr {self.__detect_denylist_cmd()}')

    disable_denylist = disable_allowlist
    add_denylist = add_allowlist
    remove_denylist = remove_allowlist
    clear_denylist = clear_allowlist

    def set_denylist(self, denylist: Optional[Collection[Union[str, Tuple[str, int]]]]):
        """Add addresses to the denylist"""
        self.clear_denylist()

        if denylist is None:
            self.disable_denylist()
        else:
            self.enable_denylist()
            for item in denylist:
                if isinstance(item, str):
                    self.add_denylist(item)
                else:
                    addr, rssi = item[0], item[1]
                    self.add_denylist(addr, rssi)

    # TODO: macfilter rss
    # TODO: macfilter rss add <extaddr> <rss>
    def set_filter_rss_add_lqi(self, extaddr: str, lqi: int):
        self.execute_command(f'macfilter addr rss add-lqi {extaddr} {lqi}')

    # TODO: macfilter rss remove <extaddr>
    # TODO: macfilter rss clear

    def __detect_allowlist_cmd(self):
        if self.api_version >= 28:
            return 'allowlist'
        else:
            return '\x77\x68\x69\x74\x65\x6c\x69\x73\x74'

    def __detect_denylist_cmd(self):
        if self.api_version >= 28:
            return 'denylist'
        else:
            return '\x62\x6c\x61\x63\x6b\x6c\x69\x73\x74'

    def __detect_networkkey_cmd(self) -> str:
        return 'networkkey' if self.api_version >= 126 else 'masterkey'

    def __detect_binary_cmd(self) -> str:
        return '-x' if self.api_version >= 28 else 'binary'

    #
    # Unicast Addresses management
    #
    def add_ipaddr(self, ip: Union[str, Ip6Addr]):
        """Add an IPv6 address to the Thread interface."""
        self.execute_command(f'ipaddr add {ip}')

    def del_ipaddr(self, ip: Union[str, Ip6Addr]):
        """Delete an IPv6 address from the Thread interface."""
        self.execute_command(f'ipaddr del {ip}')

    def get_ipaddrs(self) -> Tuple[Ip6Addr, ...]:
        """Get all IPv6 addresses assigned to the Thread interface."""
        return tuple(map(Ip6Addr, self.execute_command('ipaddr')))

    def has_ipaddr(self, ip: Union[str, ipaddress.IPv6Address]):
        """Check if a IPv6 address was added to the Thread interface."""
        return ip in self.get_ipaddrs()

    def get_ipaddr_mleid(self) -> Ip6Addr:
        """Get Thread Mesh Local EID address."""
        return self.__parse_ip6addr(self.execute_command('ipaddr mleid'))

    def get_ipaddr_linklocal(self) -> Ip6Addr:
        """Get Thread link-local IPv6 address."""
        return self.__parse_ip6addr(self.execute_command('ipaddr linklocal'))

    def get_ipaddr_rloc(self) -> Ip6Addr:
        """Get Thread Routing Locator (RLOC) address."""
        return self.__parse_ip6addr(self.execute_command('ipaddr rloc'))

    #
    # Multicast Addresses management
    #

    def add_ipmaddr(self, ip: Union[str, Ip6Addr]):
        """Subscribe the Thread interface to the IPv6 multicast address."""
        self.execute_command(f'ipmaddr add {ip}', already_is_ok=True)

    def del_ipmaddr(self, ip: Union[str, Ip6Addr]):
        """Unsubscribe the Thread interface to the IPv6 multicast address."""
        self.execute_command(f'ipmaddr del {ip}', already_is_ok=True)

    def get_ipmaddrs(self) -> Tuple[Ip6Addr, ...]:
        """Get all IPv6 multicast addresses subscribed to the Thread interface."""
        return tuple(map(Ip6Addr, self.execute_command('ipmaddr')))

    def has_ipmaddr(self, ip: Union[str, Ip6Addr]):
        """Check if a IPv6 multicast address was subscribed by the Thread interface."""
        return ip in self.get_ipmaddrs()

    def get_ipmaddr_llatn(self) -> Ip6Addr:
        """Get Link Local All Thread Nodes Multicast Address"""
        return self.__parse_ip6addr(self.execute_command('ipmaddr llatn'))

    def get_ipmaddr_rlatn(self) -> Ip6Addr:
        """Get Realm Local All Thread Nodes Multicast Address"""
        return self.__parse_ip6addr(self.execute_command('ipmaddr rlatn'))

    #
    # CCM features
    #
    def enable_ccm(self):
        """Enable Child Care Mode (CCM) for the Thread interface."""
        self.execute_command('ccm enable')

    def disable_ccm(self):
        """Disable Child Care Mode (CCM) for the Thread interface."""
        self.execute_command('ccm disable')

    #
    # Border Router utilities
    #
    def get_br_omr_prefix(self,
                          type: Optional[Literal["local", "favored"]] = None) -> Dict[str, Tuple[Ip6Prefix, str]]:
        """Get the Border Router On-Mesh Prefix."""
        prefixes: Dict[str, Tuple[Ip6Prefix, str]] = {}
        types = ('local', 'favored')
        cmd = 'br omrprefix'
        if type is not None:
            if type not in types:
                raise InvalidArgumentsError(f"Unknown type: {type}")
            cmd += f' {type}'

        output = self.execute_command(cmd)

        rex = re.compile(r'(?:(Local|Favored): )?([a-f0-9:]+/[0-9]{1,3})(?: prf:([a-z]{3,4}))?')
        for idx, line in enumerate(output):
            matched = rex.match(line)
            if matched is None:
                raise UnexpectedCommandOutput(output)

            prefix = Ip6Prefix(matched.group(2))
            prf = matched.group(3) or 'med'
            prefixes[(matched.group(1) or types[idx]).lower()] = (prefix, prf)

        return prefixes

    def br_get_onlink_prefix(self) -> Ip6Prefix:
        """Get the On-Mesh Prefix."""
        return self.__parse_prefix(self.execute_command('br onlinkprefix'))

    def br_disable(self):
        """Disable the Border Router."""
        self.execute_command('br disable')

    #
    # Backbone Router Utilities
    #

    # TODO: bbr mgmt ...
    def set_bbr_dua_response_status(self, status: int, mliid: Optional[str] = None):
        """Set Backbone Router Data Unicast Address Response status/coap-code.

        Only for testing/reference devices
        """
        _mliid = mliid if mliid is not None else ""
        self.execute_command(f'bbr mgmt dua {status} {_mliid}')

    def set_bbr_mlr_response_status(self, status: int):
        """Set Backbone Router Multicast Listener Response status."""
        self.execute_command(f'bbr mgmt mlr response {status}')

    def enable_backbone_router(self):
        """Enable Backbone Router Service for Thread 1.2 FTD.

        SRV_DATA.ntf would be triggered for attached device if there is no Backbone Router Service in
        Thread Network Data.
        """
        self.execute_command('bbr enable')

    def disable_backbone_router(self):
        """Disable Backbone Router Service for Thread 1.2 FTD.

        SRV_DATA.ntf would be triggered if Backbone Router is Primary state.
        """
        self.execute_command('bbr disable')

    def get_backbone_router_state(self) -> str:
        """Get local Backbone state (Disabled or Primary or Secondary) for Thread 1.2 FTD."""
        return self.__parse_str(self.execute_command('bbr state'))

    def get_primary_backbone_router_info(self) -> Optional[Dict[str, int]]:
        """Show current Primary Backbone Router information for Thread 1.2 device."""
        output = self.execute_command('bbr')

        if len(output) < 1:
            raise UnexpectedCommandOutput(output)

        line = output[0]
        if line == 'BBR Primary: None':
            return None

        if line != 'BBR Primary:':
            raise UnexpectedCommandOutput(output)

        # Example output:
        # BBR Primary:
        # server16: 0xE400
        # seqno:    10
        # delay:    120 secs
        # timeout:  300 secs

        dataset: Dict[str, int] = {}

        for line in output[1:]:
            key, val = line.split(':')
            key, val = key.strip(), val.strip()
            if key == 'server16':
                dataset[key] = int(val, 16)
            elif key == 'seqno':
                dataset[key] = int(val)
            elif key == 'delay':
                if not val.endswith(' secs'):
                    raise UnexpectedCommandOutput(output)
                dataset[key] = int(val.split()[0])
            elif key == 'timeout':
                if not val.endswith(' secs'):
                    raise UnexpectedCommandOutput(output)
                dataset[key] = int(val.split()[0])
            else:
                raise UnexpectedCommandOutput(output)

        return dataset

    def register_backbone_router_dataset(self):
        """Register Backbone Router Service for Thread 1.2 FTD.

        SRV_DATA.ntf would be triggered for attached device.
        """
        self.execute_command('bbr register')

    def get_backbone_router_config(self) -> Dict[str, int]:
        """Show local Backbone Router configuration for Thread 1.2 FTD."""
        output = self.execute_command('bbr config')
        # Example output:
        # seqno:    10
        # delay:    120 secs
        # timeout:  300 secs

        config: Dict[str, int] = {}

        for line in output:
            key, val = line.split(':')
            key, val = key.strip(), val.strip()
            if key == 'seqno':
                config[key] = int(val)
            elif key in ('delay', 'timeout'):
                if not line.endswith(' secs'):
                    raise UnexpectedCommandOutput(output)
                config[key] = int(val.split()[0])
            else:
                raise UnexpectedCommandOutput(output)

        return config

    def set_backbone_router_config(self,
                                   seqno: Optional[int] = None,
                                   delay: Optional[int] = None,
                                   timeout: Optional[int] = None):
        """Configure local Backbone Router configuration for Thread 1.2 FTD.

        Call register_backbone_router_dataset() to explicitly register Backbone Router service to Leader for
        Secondary Backbone Router.
        """
        if seqno is None and delay is None and timeout is None:
            raise InvalidArgumentsError("Please specify seqno or delay or timeout")

        cmd = 'bbr config'
        if seqno is not None:
            cmd += f' seqno {seqno}'

        if delay is not None:
            cmd += f' delay {delay}'

        if timeout is not None:
            cmd += f' timeout {timeout}'

        self.execute_command(cmd)

    def get_backbone_router_jitter(self) -> int:
        """Get jitter (in seconds) for Backbone Router registration for Thread 1.2 FTD."""
        return self.__parse_int(self.execute_command('bbr jitter'))

    def set_backbone_router_jitter(self, val: int):
        """Set jitter (in seconds) for Backbone Router registration for Thread 1.2 FTD."""
        self.execute_command(f'bbr jitter {val}')

    def backbone_router_get_multicast_listeners(self) -> List[Tuple[Ip6Addr, int]]:
        """Get Backbone Router Multicast Listeners."""
        listeners: List[Tuple[Ip6Addr, int]] = []
        for line in self.execute_command('bbr mgmt mlr listener'):
            ip, timeout = line.split()
            listeners.append((Ip6Addr(ip), int(timeout)))

        return listeners

    #
    # Thread 1.2 and DUA/MLR utilities
    #

    def get_domain_name(self) -> str:
        """Get the Thread Domain Name for Thread 1.2 device."""
        return self.__parse_str(self.execute_command('domainname'))

    def set_domain_name(self, name: str):
        """Set the Thread Domain Name for Thread 1.2 device."""
        self.execute_command('domainname %s' % self.__escape_escapable(name))

    def get_dua_iid(self) -> str:
        """Get the DUA IID for Thread 1.2 device."""
        raw_iid = self.execute_command('dua iid')
        if raw_iid:
            return self.__parse_iid(raw_iid)
        else:
            return ''

    def set_dua_iid(self, iid: str):
        """Set the DUA IID for Thread 1.2 device."""
        self.__validate_iid(iid)
        self.execute_command(f'dua iid {iid}')

    def clear_dua_iid(self):
        """Clear the DUA IID for Thread 1.2 device."""
        self.execute_command('dua iid clear')

    # TODO: mlr reg <ipaddr> ... [timeout]

    #
    # Link metrics management
    #

    def linkmetrics_config_enhanced_ack_clear(self, peer_addr: Union[str, Ip6Addr]) -> bool:
        output = self.execute_command(f'linkmetrics config {peer_addr} enhanced-ack clear')
        return self.__parse_linkmetrics_mgmt_response(peer_addr, output)

    def linkmetrics_config_enhanced_ack_register(self,
                                                 peer_addr: Union[str, Ip6Addr],
                                                 link_metrics_flags: str,
                                                 reference: bool = False) -> bool:
        if self.__valid_flags(link_metrics_flags, 'qmr') is False:
            raise ValueError(link_metrics_flags)

        output = self.execute_command(
            f'linkmetrics config {peer_addr} enhanced-ack register {link_metrics_flags} {"r" if reference else ""}')
        return self.__parse_linkmetrics_mgmt_response(peer_addr, output)

    def linkmetrics_config_forward(self, peer_addr: Union[str, Ip6Addr], seriesid: int, series_flags: str,
                                   link_metrics_flags: str) -> bool:
        if self.__valid_flags(series_flags, 'ldraX') is False:
            raise ValueError(series_flags)

        if self.__valid_flags(link_metrics_flags, 'pqmr') is False:
            raise ValueError(link_metrics_flags)

        output = self.execute_command(
            f'linkmetrics config {peer_addr} forward {seriesid} {series_flags} {link_metrics_flags}')
        return self.__parse_linkmetrics_mgmt_response(peer_addr, output)

    def linkmetrics_probe(self, peer_addr: Union[str, Ip6Addr], seriesid: int, length: int):
        if length < 0 or length > 64:
            raise ValueError(length)

        self.execute_command(f'linkmetrics probe {peer_addr} {seriesid} {length}')

    def linkmetrics_request_single(self, peer_addr: Union[str, Ip6Addr], link_metrics_flags: str) -> Dict[str, int]:
        if self.__valid_flags(link_metrics_flags, 'pqmr') is False:
            raise ValueError(link_metrics_flags)

        output = self.execute_command(f'linkmetrics request {peer_addr} single {link_metrics_flags}')
        return self.__parse_linkmetrics_report(peer_addr, output)

    def linkmetrics_request_forward(self, peer_addr: Union[str, Ip6Addr], seriesid: int) -> Dict[str, int]:
        output = self.execute_command(f'linkmetrics request {peer_addr} forward {seriesid}')
        return self.__parse_linkmetrics_report(peer_addr, output)

    def __parse_linkmetrics_mgmt_response(self, peer_addr: Union[str, Ip6Addr], output: List[str]) -> bool:
        #
        # Example output:
        #
        # Received Link Metrics Management Response from: fe80:0:0:0:3092:f334:1455:1ad2
        # Status: Success
        # Done
        #

        status = ''
        report_received = False

        for line in output:
            if 'Received Link Metrics Management Response from' in line:
                address = line.split(': ')[1].strip()
                report_received = address == peer_addr
            elif 'Status' in line:
                status = line.split(':')[1].strip()

        return report_received and status == 'Success'

    def __parse_linkmetrics_report(self, peer_addr: Union[str, Ip6Addr], output: List[str]) -> Dict[str, int]:
        #
        # Example output:
        #
        # Received Link Metrics Report from: fe80:0:0:0:3092:f334:1455:1ad2
        #
        # - PDU Counter: 2 (Count/Summation)
        # - LQI: 76 (Exponential Moving Average)
        # - Margin: 82 (dB) (Exponential Moving Average)
        # - RSSI: -18 (dBm) (Exponential Moving Average)
        # Done
        #

        results: Dict[str, int] = {}
        report_received = False

        for line in output:
            if 'Received Link Metrics Report' in line:
                address = line.split(': ')[1].strip()
                report_received = address == peer_addr
            elif 'Received Link Metrics data in Enh Ack from neighbor' in line:
                # If the Enhanced-ACK Based Probing is enabled, the CLI will output the following
                # link metrics info after executing the `linkmetrics request` command. This case is
                # used to skip these Enhanced-ACK related link metrics info.
                #
                # Received Link Metrics data in Enh Ack from neighbor, short address:0x3400 ,
                #                                                      extended address:c6a24d6514cf9178
                # - LQI: 224 (Exponential Moving Average)
                # - Margin: 0 (dB) (Exponential Moving Average)
                #
                # Received Link Metrics Report from: fe80:0:0:0:3092:f334:1455:1ad2
                #
                # - PDU Counter: 2 (Count/Summation)
                # - LQI: 76 (Exponential Moving Average)
                # - Margin: 82 (dB) (Exponential Moving Average)
                # - RSSI: -18 (dBm) (Exponential Moving Average)
                # Done
                #
                report_received = False

            if not report_received:
                continue

            if '- LQI' in line:
                results['lqi'] = self.__parse_numbers(line)[0]
            elif '- Margin' in line:
                results['margin'] = self.__parse_numbers(line)[0]
            elif '- RSSI' in line:
                results['rssi'] = self.__parse_numbers(line)[0]
            elif '- PDU Counter' in line:
                results['pdu_counter'] = self.__parse_numbers(line)[0]

        return results

    def __parse_numbers(self, line: str) -> List[int]:
        values = re.findall(r"-?\d+", line)
        return list(map(int, values))

    def __valid_flags(self, flags: str, flags_set: str):
        # check for duplicate chars
        if len(flags) != len(set(flags)):
            return False

        return set(flags).issubset(set(flags_set))

    #
    # Logging
    #

    def get_log_level(self) -> int:
        """Get the log level."""
        return self.__parse_int(self.execute_command('log level'))

    def set_log_level(self, level: int):
        """Set the log level."""
        self.execute_command(f'log level {level}')

    #
    # Device performance related information
    #

    def get_message_buffer_info(self) -> Dict[str, Union[int, Tuple[int, ...]]]:
        """Get the current message buffer information."""
        output = self.execute_command('bufferinfo')

        info: Dict[str, Union[int, Tuple[int, ...]]] = {}

        def _parse_val(val: str):
            vals = val.split()
            return int(vals[0]) if len(vals) == 1 else tuple(map(int, vals))

        for line in output:
            key, val = line.split(':')
            key, val = key.strip(), val.strip()
            info[key.replace(' ', '_')] = _parse_val(val)

        return info

    @constant_property
    def counter_names(self):
        """Get the supported counter names."""
        return tuple(self.execute_command('counters'))

    def get_counter(self, name: str) -> Counter[str]:
        """Reset the counter value."""
        output = self.execute_command(f'counters {name}')

        counter: Counter[str] = Counter()
        for line in output:
            k, v = line.strip().split(': ')
            counter[k] = int(v)

        return counter

    def reset_counter(self, name: str):
        """Reset the counter value."""
        self.execute_command(f'counters {name} reset')

    def get_eidcache(self) -> Dict[Ip6Addr, Rloc16]:
        """Get the EID-to-RLOC cache entries."""
        output = self.execute_command('eidcache')
        cache: Dict[Ip6Addr, Rloc16] = {}

        for line in output:
            ip, rloc16, _ = line.split(" ", 2)

            cache[Ip6Addr(ip)] = Rloc16(rloc16, 16)

        return cache

    #
    # UDP utilities
    #

    def udp_open(self):
        """Opens the example socket."""
        self.execute_command('udp open')

    def udp_close(self):
        """Opens the example socket."""
        self.execute_command('udp close')

    def udp_bind(self, ip: str, port: int, netif: NetifIdentifier = NetifIdentifier.THREAD):
        """Assigns a name (i.e. IPv6 address and port) to the example socket.

        :param ip: the IPv6 address or the unspecified IPv6 address (::).
        :param port: the UDP port
        """
        bindarg = ''
        if netif == NetifIdentifier.UNSPECIFIED:
            bindarg += ' -u'
        elif netif == NetifIdentifier.BACKBONE:
            bindarg += ' -b'

        self.execute_command(f'udp bind{bindarg} {ip} {port}')

    def udp_connect(self, ip: str, port: int):
        """Specifies the peer with which the socket is to be associated.

        ip: the peer's IPv6 address.
        port: the peer's UDP port.
        """
        self.execute_command(f'udp connect {ip} {port}')

    def udp_send(self,
                 ip: Optional[Union[str, Ip6Addr]] = None,
                 port: Optional[int] = None,
                 text: Optional[str] = None,
                 random_bytes: Optional[int] = None,
                 hex: Optional[str] = None,
                 return_result: bool = True):
        """Send a few bytes over UDP.

        ip: the IPv6 destination address.
        port: the UDP destination port.
        type: the type of the message:
            _ -t: text payload in the value, same as without specifying the type.
            _ -s: auto-generated payload with specified length indicated in the value.
        * -x: binary data in hexadecimal representation in the value.
        """
        if (ip is None) != (port is None):
            raise InvalidArgumentsError("Please specify both `ip` and `port`.")

        if (text is not None) + (random_bytes is not None) + (hex is not None) != 1:
            raise InvalidArgumentsError("Please specify `text` or `random_bytes` or `hex`.")

        cmd = 'udp send'

        if ip is not None:
            cmd += f' {ip} {port}'

        if text is not None:
            cmd += f' -t {text}'
        elif random_bytes is not None:
            cmd += f' -s {random_bytes}'
        elif hex is not None:
            self.__validate_hex(hex)
            cmd += f' -x {hex}'

        self.execute_command(cmd, ignore_result=not return_result)

    def udp_get_link_security(self) -> bool:
        """Gets whether the link security is enabled or disabled."""
        return self.__parse_Enabled_or_Disabled(self.execute_command('udp linksecurity'))

    def udp_enable_link_security(self):
        """Enable link security."""
        self.execute_command('udp linksecurity enable')

    def udp_disable_link_security(self):
        """Disable link security."""
        self.execute_command('udp linksecurity disable')

    def netstat(self) -> List[Tuple[Tuple[Ip6Addr, int], Tuple[Ip6Addr, int]]]:
        cmd = 'netstat'
        output = self.execute_command(cmd)
        if len(output) < 2:
            raise UnexpectedCommandOutput(output)

        socks: List[Tuple[Tuple[Ip6Addr, int], Tuple[Ip6Addr, int]]] = []
        for line in output[2:]:
            _, sock_addr, peer_addr = line.strip().split('|')[:3]
            sock_addr = self.__parse_socket_addr(sock_addr.strip())
            peer_addr = self.__parse_socket_addr(peer_addr.strip())
            socks.append((sock_addr, peer_addr))

        return socks

    @staticmethod
    def __parse_socket_addr(addr: str) -> Tuple[Ip6Addr, int]:
        addr, port = addr.rsplit(':', 1)
        if addr.startswith('[') and addr.endswith(']'):
            addr = addr[1:-1]

        return Ip6Addr(addr), int(port) if port != '*' else 0

    #
    # CoAP CLI (test) utilities
    #
    def coap_start(self):
        """Starts the application coap service."""
        self.execute_command('coap start')

    def coap_stop(self):
        """Stops the application coap service."""
        self.execute_command('coap stop')

    def coap_get(self, addr: Union[str, Ip6Addr], uri_path: str, type: str = "con"):
        cmd = f'coap get {addr} {uri_path} {type}'
        self.execute_command(cmd)

    def coap_put(self, addr: Union[str, Ip6Addr], uri_path: str, type: str = "con", payload: Optional[str] = None):
        cmd = f'coap put {addr} {uri_path} {type}'

        if payload is not None:
            cmd += f' {payload}'

        self.execute_command(cmd)

    def coap_post(self, addr: Union[str, Ip6Addr], uri_path: str, type: str = "con", payload: Optional[str] = None):
        cmd = f'coap post {addr} {uri_path} {type}'

        if payload is not None:
            cmd += f' {payload}'

        self.execute_command(cmd)

    def coap_delete(self, addr: Union[str, Ip6Addr], uri_path: str, type: str = "con", payload: Optional[str] = None):
        cmd = f'coap delete {addr} {uri_path} {type}'

        if payload is not None:
            cmd += f' {payload}'

        self.execute_command(cmd)

    def coap_get_test_resource_path(self) -> str:
        """Gets the URI path for the test resource."""
        return self.__parse_str(self.execute_command('coap resource'))

    def coap_set_test_resource_path(self, path: str):
        """Sets the URI path for the test resource."""
        self.execute_command(f'coap resource {path}')

    def coap_test_set_resource_content(self, content: str):
        """Sets the content sent by the test resource. If a CoAP client is observing the resource, a notification is
           sent to that client."""
        self.execute_command(f'coap set {content}')

    # TODO: coap observe <address> <uri-path> [type]
    # TODO: coap cancel
    # TODO: coap parameters <type> ["default"|<ack_timeout> <ack_random_factor_numerator> <ack_random_factor_denominator> <max_retransmit>]
    # TODO: CoAP Secure utilities

    #
    # Diag Utilities
    #
    def diag(self):
        """Get the current status of the diagnostics module."""
        return self.__parse_str(self.execute_command('diag'))

    def diag_start(self):
        """Start diagnostics mode."""
        self.execute_command('diag start')

    def diag_stop(self):
        """Stop diagnostics mode."""
        self.execute_command('diag stop')

    def diag_set_channel(self, channel: int):
        """Set the IEEE 802.15.4 Channel value for diagnostics module."""
        self.execute_command(f'diag channel {channel}')

    def diag_get_channel(self) -> int:
        """Get the IEEE 802.15.4 Channel value for diagnostics module."""
        return self.__parse_int(self.execute_command('diag channel'))

    def diag_set_power(self, power: int):
        """Set the tx power value(dBm) for diagnostics module."""
        self.execute_command(f'diag power {power}')

    def diag_get_power(self) -> int:
        """Get the tx power value(dBm) for diagnostics module."""
        return self.__parse_int(self.execute_command('diag power'))

    def diag_cw_start(self):
        """Start transmitting continuous carrier wave."""
        self.execute_command('diag cw start')

    def diag_cw_stop(self):
        """Stop transmitting continuous carrier wave."""
        self.execute_command('diag cw stop')

    def diag_frame(self,
                   frame: str,
                   max_csma_backoffs: Optional[int] = None,
                   csma_ca_enabled: Optional[bool] = None,
                   rx_channel_after_tx_done: Optional[int] = None,
                   tx_delay: Optional[int] = None,
                   tx_power: Optional[int] = None,
                   max_frame_retries: Optional[int] = None,
                   is_security_processed: Optional[bool] = None,
                   is_header_updated: Optional[bool] = None):
        """Set the frame (hex encoded) to be used by `diag send` and `diag repeat`."""
        command = f'diag frame '
        command += self.__get_optional_int_argument('-b', max_csma_backoffs)
        command += self.__get_optional_int_argument('-d', tx_delay)
        command += self.__get_optional_int_argument('-C', rx_channel_after_tx_done)
        command += self.__get_optional_int_argument('-p', tx_power)
        command += self.__get_optional_int_argument('-r', max_frame_retries)
        command += self.__get_optional_bool_argument('-c', csma_ca_enabled)
        command += self.__get_optional_bool_argument('-s', is_security_processed)
        command += self.__get_optional_bool_argument('-u', is_header_updated)
        command += f'{frame}'

        self.execute_command(command)

    def diag_stream_start(self):
        """Start transmitting a stream of characters."""
        self.execute_command('diag stream start')

    def diag_stream_stop(self):
        """Stop transmitting a stream of characters."""
        self.execute_command('diag stream stop')

    def diag_send(self, packets: int, length: Optional[int] = None, is_async: bool = True):
        """Transmit a fixed number of packets."""
        command = 'diag send '
        command += 'async ' if is_async else ''
        command += f'{packets} '
        command += f'{length}' if length is not None else ''

        self.execute_command(command)

    def diag_repeat(self, delay: int, length: Optional[int] = None):
        """Transmit packets repeatedly with a fixed interval."""
        if length is None:
            command = f'diag repeat {delay}'
        else:
            command = f'diag repeat {delay} {length}'
        self.execute_command(command)

    def diag_repeat_stop(self):
        """Stop repeated packet transmission."""
        self.execute_command('diag repeat stop')

    def diag_radio_sleep(self):
        """Enter radio sleep mode."""
        self.execute_command('diag radio sleep')

    def diag_radio_enable(self):
        """Enable the radio."""
        self.execute_command('diag radio enable')

    def diag_radio_disable(self):
        """Disable the radio."""
        self.execute_command('diag radio disable')

    def diag_radio_receive(self):
        """Set radio to receive mode."""
        self.execute_command('diag radio receive')

    def diag_radio_receive_number(self, number: int) -> List[Dict[str, Union[int, str]]]:
        """Set radio to receive mode and receive specified number of packets."""
        #
        # The `diag radio receive <number> [lpr]` command example:
        #
        # > diag radio receive 5 lpr
        # 0, rssi:-49, lqi:119, len:10, psdu:000102030405060771e
        # 1, rssi:-51, lqi:112, len:10, psdu:000102030405060771e
        # 2, rssi:-42, lqi:120, len:10, psdu:000102030405060771e
        # 3, rssi:-54, lqi:111, len:10, psdu:000102030405060771e
        # 4, rssi:-56, lqi:108, len:10, psdu:000102030405060771e
        # Done
        #

        output = self.execute_command(f'diag radio receive {number} lpr')

        if len(output) != number:
            raise UnexpectedCommandOutput(output)

        result: List[Dict[str, Union[int, str]]] = []

        for line in output:
            data = line.split(',')

            if len(data) != 5:
                raise UnexpectedCommandOutput(data)

            result.append({
                'rssi': int(data[1].split(":")[1]),
                'lqi': int(data[2].split(":")[1]),
                'len': int(data[3].split(":")[1]),
                'psdu': data[4].split(":")[1],
            })

        return result

    def diag_enable_radio_receive_filter(self):
        """Enable the radio receive filter."""
        self.execute_command('diag radio receive filter enable')

    def diag_disable_radio_receive_filter(self):
        """Disable the radio receive filter."""
        self.execute_command('diag radio receive filter disable')

    def diag_set_radio_receive_filter_dest_mac_address(self, dest_mac_address: str):
        """Set the destination mac address of the radio receive filter."""
        self.execute_command(f'diag radio receive filter {dest_mac_address}')

    def diag_get_radio_state(self) -> str:
        """Get the state of the radio."""
        return self.__parse_str(self.execute_command('diag radio state'))

    def diag_get_stats(self) -> Dict[str, int]:
        """Get statistics during diagnostics mode."""
        #
        # The command 'diag stats' output example:
        #
        # > diag stats
        # received packets: 10
        # sent success packets: 10
        # sent error cca packets: 0
        # sent error abort packets: 0
        # sent error others packets: 0
        # first received packet: rssi=-65, lqi=101
        # last received packet: rssi=-64, lqi=98
        # Done
        #
        output = self.execute_command('diag stats')
        if len(output) < 7:
            raise UnexpectedCommandOutput(output)

        result: Dict[str, int] = {}

        result['received_packets'] = int(output[0].split(":")[1])
        result['sent_success_packets'] = int(output[1].split(":")[1])
        result['sent_error_cca_packets'] = int(output[2].split(":")[1])
        result['sent_error_abort_packets'] = int(output[3].split(":")[1])
        result['sent_error_invalid_state_packets'] = int(output[4].split(":")[1])
        result['sent_error_others_packets'] = int(output[5].split(":")[1])

        values = re.findall(r"-?\d+", output[6])
        result['first_received_packet_rssi'] = int(values[0])
        result['first_received_packet_lqi'] = int(values[1])

        values = re.findall(r"-?\d+", output[7])
        result['last_received_packet_rssi'] = int(values[0])
        result['last_received_packet_lqi'] = int(values[1])

        return result

    def diag_stats_clear(self):
        """Clear statistics during diagnostics mode."""
        self.execute_command('diag stats clear')

    def diag_set_gpio_value(self, gpio: int, value: int):
        """Set the gpio value."""
        self.execute_command(f'diag gpio set {gpio} {value}')

    def diag_get_gpio_value(self, gpio: int) -> int:
        """Get the gpio value."""
        return int(self.__parse_str(self.execute_command(f'diag gpio get {gpio}')))

    def diag_set_gpio_mode(self, gpio: int, mode: str):
        """Set the gpio mode."""
        self.execute_command(f'diag gpio mode {gpio} {mode}')

    def diag_get_gpio_mode(self, gpio: int) -> str:
        """Get the gpio mode."""
        return self.__parse_str(self.execute_command(f'diag gpio mode {gpio}'))

    def diag_echo(self, message: str) -> str:
        """RCP echoes the given message."""
        return self.__parse_str(self.execute_command(f'diag echo {message}'))

    def diag_echo_number(self, number: int) -> str:
        """RCP echoes the given message."""
        return self.__parse_str(self.execute_command(f'diag echo -n {number}'))

    def diag_get_powersettings(self) -> List[Dict[str, Any]]:
        """Get the currently used power settings table."""
        #
        # The command 'diag powersettings' output example:
        #
        # > diag powersettings
        # | StartCh | EndCh | TargetPower | ActualPower | RawPowerSetting |
        # +---------+-------+-------------+-------------+-----------------+
        # |      11 |    14 |        1700 |        1000 |          223344 |
        # |      15 |    24 |        2000 |        1900 |          112233 |
        # |      25 |    25 |        1600 |        1000 |          223344 |
        # |      26 |    26 |        1600 |        1500 |          334455 |
        # Done
        #
        result: List[Dict[str, Union[int, bytes]]] = []
        output = self.execute_command(f'diag powersettings')

        if len(output) < 3:
            raise UnexpectedCommandOutput(output)

        if not output[-1].startswith('Done'):
            raise UnexpectedCommandOutput(output)

        for line in output[2:-1]:
            data = line.split('|')

            result.append({
                'channel_start': int(data[1]),
                'channel_end': int(data[2]),
                'target_power': int(data[3]),
                'actual_power': int(data[4]),
                'raw_power_setting': self.__hex_to_bytes(data[5].lstrip().rstrip()),
            })

        return result

    def diag_get_channel_powersettings(self, channel: int) -> Dict[str, Any]:
        """Gets the currently used power settings for the given channel."""
        #
        # The command 'diag powersettings <channel>' output example:
        #
        # > diag powersettings 11
        # TargetPower(0.01dBm): 1700
        # ActualPower(0.01dBm): 1000
        # RawPowerSetting: 223344
        # Done
        #
        result: Dict[str, Union[int, bytes]] = {}
        output = self.execute_command(f'diag powersettings {channel}')

        if len(output) != 4:
            raise UnexpectedCommandOutput(output)

        if not output[-1].startswith('Done'):
            raise UnexpectedCommandOutput(output)

        result['target_power'] = int(output[0].split(':')[1])
        result['actual_power'] = int(output[1].split(':')[1])
        result['raw_power_setting'] = self.__hex_to_bytes(output[2].split(':')[1].lstrip().rstrip())

        return result

    def diag_get_rawpowersetting(self) -> str:
        """Get the raw power setting."""
        return self.__parse_str(self.execute_command('diag rawpowersetting'))

    def diag_set_rawpowersetting(self, rawpowersetting: str):
        """Set the raw power setting."""
        self.execute_command(f'diag rawpowersetting {rawpowersetting}')

    def diag_enable_rawpowersetting(self):
        """Enable the raw power setting."""
        self.execute_command('diag rawpowersetting enable')

    def diag_disable_rawpowersetting(self):
        """Disable the raw power setting."""
        self.execute_command('diag rawpowersetting disable')

    def is_command_supported(self, command: str) -> bool:
        """Check whether the the given command is supported by the device."""
        output = self.__otcmd.execute_command(command, timeout=10)

        if re.match(r"Error \d+: \w*", output[-1]):
            return False

        return True

    #
    # Network management utilities
    #
    def create_dataset(self,
                       active_timestamp: Optional[int] = None,
                       channel: Optional[int] = None,
                       channel_mask: Optional[int] = None,
                       extpanid: Optional[str] = None,
                       mesh_local_prefix: Optional[str] = None,
                       network_key: Optional[str] = None,
                       network_name: Optional[str] = None,
                       panid: Optional[int] = None,
                       pskc: Optional[str] = None,
                       security_policy: Optional[tuple[int, str]] = None,
                       pending_timestamp: Optional[int] = None,
                       wakeup_channel: Optional[int] = None) -> bytes:
        """Creates a new Operational Dataset with given parameters."""
        self.dataset_clear_buffer()
        self.dataset_init_buffer()
        self.dataset_set_buffer(active_timestamp, channel, wakeup_channel, channel_mask, extpanid, mesh_local_prefix,
                                network_key, network_name, panid, pskc, security_policy, pending_timestamp)
        return self.get_dataset_tlvs_bytes()

    def join(self, dataset: bytes) -> None:
        """Joins to a Thread network with given Active Operational Dataset."""
        self.set_dataset_bytes('active', dataset)
        self.ifconfig_up()
        self.thread_start()

    def leave(self) -> None:
        """Leaves from the Thread network."""
        self.thread_stop()
        self.ifconfig_down()

    def wait_for(self, command: str, expect_line: Union[str, Pattern[str], Collection[str]], timeout: float = 60):
        """Wait for the expected output by periodically executing the given command."""
        success = False

        while timeout > 0:
            output = self.execute_command(command)
            if any(match_line(line, expect_line) for line in output):
                success = True
                break

            self.__otcmd.wait(1)
            timeout -= 1

        if not success:
            raise ExpectLineTimeoutError(expect_line)

    #
    # Other TODOs
    #

    def get_network_diagnostics(self, addr: Union[str, Ip6Addr],
                                tlvs: list[int]) -> Dict[str, Union[str, Dict[str, str]]]:
        """Get the network diagnostic information."""
        args = [str(addr)] + list(map(str, tlvs))
        output = self.execute_command(f'networkdiagnostic get {" ".join(args)}')
        # line 0 is the hex representation of the diagnostics
        # below that is the human readable/parsed format
        result: Dict[str, Union[str, Dict[str, str]]] = {}
        diag: Optional[Union[str, Dict[str, str]]] = None
        for line in output[1:]:
            if not line.startswith(' '):
                k, v = line.split(': ', 1)
                diag = v or {}
                result[line.split(': ', 1)[0]] = diag
            else:
                assert diag is not None and isinstance(diag, dict)
                k, v = line.strip().split(': ')
                diag[k] = v
        return result

    def get_network_diagnostics_bytes(self, addr: Union[str, Ip6Addr], tlvs: list[int]) -> str:
        """Get the network diagnostic information."""
        args = [str(addr)] + list(map(str, tlvs))
        output = self.execute_command(f'networkdiagnostic get {" ".join(args)}')
        # line 0 is the hex representation of the diagnostics
        # below that is the human readable/parsed format
        return output[0].split(': ')[1]

    def reset_network_diagnostics(self, addr: Union[str, Ip6Addr], type: list[int]):
        """Reset the network diagnostic information."""
        self.execute_command(f'networkdiagnostic reset {addr} {" ".join(map(str, type))}')

    def get_network_diagnostics_non_preferred_channels(self) -> int:
        """Get the non-preferred channels in the network diagnostics."""
        return self.__parse_int(self.execute_command('networkdiagnostic nonpreferredchannels'), 16)

    def set_network_diagnostics_non_preferred_channels(self, channels: int):
        """Set the non-preferred channels in the network diagnostics."""
        self.execute_command(f'networkdiagnostic nonpreferredchannels {channels}')

    __PARENT_KEY_MAP = {
        'Ext Addr': 'extaddr',
        'Rloc': 'rloc16',
        'Link Quality In': 'lq_in',
        'Link Quality Out': 'lq_out',
        'Age': 'age',
        'Version': 'version',
        'CSL clock accuracy': 'csl_clock_accuracy',
        'CSL uncertainty': 'csl_uncertainty',
    }

    def get_parent(self) -> Dict[str, Union[int, str]]:
        """Get the diagnostic information for a Thread Router as parent."""
        data: Dict[str, Union[int, str]] = {}
        output = self.execute_command('parent')

        try:
            for line in output:
                k, v = line.split(': ')
                if OTCI.__PARENT_KEY_MAP[k] == 'extaddr':
                    data[OTCI.__PARENT_KEY_MAP[k]] = v
                elif OTCI.__PARENT_KEY_MAP[k] == 'rloc16':
                    data[OTCI.__PARENT_KEY_MAP[k]] = Rloc16(v, 16)
                else:
                    data[OTCI.__PARENT_KEY_MAP[k]] = int(v, base=0)
        except KeyError:
            raise UnexpectedCommandOutput(output)

        return data

    # TODO: pskc [-p] <key>|<passphrase>
    #

    #
    # Platform Commands Utilities
    #
    def support_iperf3(self) -> bool:
        """Check whether the platform supports iperf3."""
        #
        # Command example:
        #
        # $ command -v iperf3
        # /usr/bin/iperf3
        #
        ret = False
        output = self.execute_platform_command('command -v iperf3')
        if len(output) > 0 and 'iperf3' in output[0]:
            ret = True

        return ret

    def iperf3_client(self,
                      host: Union[str, Ip6Addr],
                      ipv6: bool = True,
                      udp: bool = True,
                      bind_address: Optional[Union[str, Ip6Addr]] = None,
                      bitrate: int = 10000,
                      interval: int = 10,
                      transmit_time: int = 10,
                      length: Optional[int] = None) -> Dict[str, Dict[str, Any]]:
        """Run iperf3 in client mode.

        :param host: The host IPv6 address to send iperf3 traffic.
        :param ipv6: True to use IPv6, False to use IPv4 (default IPv6).
        :param udp: True to use UDP, False to use TCP (default UDP).
        :param bind_address: The local address to be bound.
        :param bitrate: The target bitrate in bits/sec (default 10000 bit/sec).
        :param interval: Seconds between periodic throughput reports (default 10 sec).
        :param transmit_time: Time in seconds to transmit for (default 10 secs)
        :param length: Length of buffer to read or write (default None).
        """
        #
        # Iperf3 client example:
        #
        # $ iperf3 -6 -c fdd6:f5cf:d32d:8d88:a98b:cf7c:2ed2:691a -u -b 90000 -i 20 -t 10 -l 1232 -f k
        # Connecting to host fdd6:f5cf:d32d:8d88:a98b:cf7c:2ed2:691a, port 5201
        # [  5] local fdd6:f5cf:d32d:8d88:0:ff:fe00:fc00 port 59495 connected to fdd6:f5cf:d32d:8d88:a98b:cf7c:2ed2:691a port 5201
        # [ ID] Interval           Transfer     Bitrate         Total Datagrams
        # [  5]   0.00-10.00  sec   111 KBytes  90.7 Kbits/sec  92
        # - - - - - - - - - - - - - - - - - - - - - - - - -
        # [ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
        # [  5]   0.00-10.00  sec   111 KBytes  90.7 Kbits/sec  0.000 ms  0/92 (0%)  sender
        # [  5]   0.00-10.96  sec  99.9 KBytes  74.7 Kbits/sec  30.157 ms  9/92 (9.8%)  receiver
        #
        # iperf Done.
        #

        wait_time = 10
        client_option = f'-c {host}'
        version_option = "-6" if ipv6 else "-4"
        udp_option = '-u' if udp else ''
        bind_option = f'-B {bind_address}' if bind_address else ''
        bitrate_option = f'-b {bitrate}'
        interval_option = f'-i {interval}'
        time_option = f'-t {transmit_time}'
        length_option = f'-l {length}' if length else ''
        format_option = '-f k'

        cmd = (f'iperf3 {version_option} {client_option} {udp_option} {bitrate_option} {interval_option} ' +
               f'{time_option} {length_option} {format_option}')
        output = self.execute_platform_command(cmd, timeout=transmit_time + wait_time)

        results: Dict[str, Any] = {}
        for line in output:
            fields = line.split()
            if len(fields) != 13:
                continue

            if fields[-1] == 'sender':
                results['sender'] = self.__parse_iperf3_report(line)
            elif fields[-1] == 'receiver':
                results['receiver'] = self.__parse_iperf3_report(line)

        return results

    def iperf3_server(self,
                      bind_address: Optional[Union[str, Ip6Addr]] = None,
                      interval: int = 10,
                      timeout: int = 60) -> Dict[str, Any]:
        """Run iperf3 in server mode.

        :param bind_address: The local address to be bound.
        :param interval: Seconds between periodic throughput reports (default 10 sec).
        :param timeout: Timeout in seconds to abort the program (default 60 secs)
        """
        #
        # Iperf3 server example:
        #
        # $ iperf3 -s -1 -B fdd6:f5cf:d32d:8d88:a98b:cf7c:2ed2:691a -i 50 -f k
        # -----------------------------------------------------------
        # Server listening on 5201
        # -----------------------------------------------------------
        # Accepted connection from fdd6:f5cf:d32d:8d88:0:ff:fe00:fc00, port 44080
        # [  5] local fdd6:f5cf:d32d:8d88:a98b:cf7c:2ed2:691a port 5201 connected to fdd6:f5cf:d32d:8d88:0:ff:fe00:fc00 port 59495
        # [ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
        # [  5]   0.00-10.96  sec  99.9 KBytes  74.7 Kbits/sec  30.157 ms  9/92 (9.8%)
        # - - - - - - - - - - - - - - - - - - - - - - - - -
        # [ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
        # [  5]   0.00-10.96  sec  99.9 KBytes  74.7 Kbits/sec  30.157 ms  9/92 (9.8%)  receiver
        #

        bind_option = f'-B {bind_address}' if bind_address else ''
        interval_option = f'-i {interval}'
        format_option = '-f k'

        cmd = f'iperf3 -s -1 {bind_option} {interval_option} {format_option}'
        output = self.execute_platform_command(cmd, timeout)

        results = {}
        for line in output:
            fields = line.split()
            if len(fields) == 13 and fields[-1] == 'receiver':
                results = self.__parse_iperf3_report(line)

        return results

    def __parse_iperf3_report(self, line: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        fields = line.split()
        format_unit = 1000

        if len(fields) == 13 and (fields[-1] == 'sender' or fields[-1] == 'receiver'):
            results['id'] = int(fields[1].replace(']', ''))
            results['interval_start'] = float(fields[2].split('-')[0])
            results['interval_end'] = float(fields[2].split('-')[1])
            results['transfer'] = int(float(fields[4]) * format_unit)
            results['bitrate'] = int(float(fields[6]) * format_unit)
            results['jitter'] = float(fields[8])
            results['lossrate'] = float(fields[11].replace('(', '').replace(')', '').replace('%', '')) / 100
            results['datagrams'] = fields[12]

        return results

    #
    # Private methods
    #

    def __parse_str(self, output: List[str]) -> str:
        if len(output) != 1:
            raise UnexpectedCommandOutput(output)

        return output[0]

    def __parse_int_list(self, output: List[str]) -> List[int]:
        line = self.__parse_str(output)
        return list(map(int, line.strip().split()))

    def __parse_ip6addr(self, output: List[str]) -> Ip6Addr:
        return Ip6Addr(self.__parse_str(output))

    def __parse_ip6addr_list(self, output: List[str]) -> List[Ip6Addr]:
        return [Ip6Addr(line) for line in output]

    def __parse_int(self, output: List[str], base: int = 10) -> int:
        if len(output) != 1:
            raise UnexpectedCommandOutput(output)

        return int(output[0], base)

    def __parse_network_key(self, output: List[str]) -> str:
        networkkey = self.__parse_str(output)

        try:
            self.__validate_network_key(networkkey)
        except ValueError:
            raise UnexpectedCommandOutput(output)

        return networkkey

    def __validate_network_key(self, networkkey: str):
        if len(networkkey) != 32:
            raise ValueError(networkkey)

        int(networkkey, 16)

    def __parse_hex64b(self, output: List[str]) -> str:
        extaddr = self.__parse_str(output)

        try:
            self.__validate_hex64b(extaddr)
        except ValueError:
            raise UnexpectedCommandOutput(output)

        return extaddr

    __parse_extaddr = __parse_hex64b
    __parse_extpanid = __parse_hex64b
    __parse_eui64 = __parse_hex64b
    __parse_joiner_id = __parse_hex64b
    __parse_iid = __parse_hex64b

    def __validate_hex64b(self, extaddr: str):
        if len(extaddr) != 16:
            raise ValueError(extaddr)

        self.__validate_hex(extaddr)

    def __validate_hex(self, hexstr: str):
        if len(hexstr) % 2 != 0:
            raise ValueError(hexstr)

        for i in range(0, len(hexstr), 2):
            int(hexstr[i:i + 2], 16)

    __validate_extaddr = __validate_hex64b
    __validate_extpanid = __validate_hex64b
    __validate_iid = __validate_hex64b

    def __parse_Enabled_or_Disabled(self, output: List[str]) -> bool:
        return self.__parse_values(output, Enabled=True, Disabled=False)

    def __parse_values(self, output: List[str], **vals: Any) -> Any:
        val = self.__parse_str(output)
        if val not in vals:
            raise UnexpectedCommandOutput(output)

        return vals[val]

    def __validate_hex_or_bytes(self, data: Union[str, bytes]) -> str:
        if isinstance(data, bytes):
            return ''.join('%02x' % c for c in data)
        elif isinstance(data, str):
            self.__validate_hex(data)
            return data
        else:
            raise TypeError(f"Type {type(data)} is not supported.")

    def __hex_to_bytes(self, hexstr: str) -> bytes:
        self.__validate_hex(hexstr)
        return bytes(int(hexstr[i:i + 2], 16) for i in range(0, len(hexstr), 2))

    def __bytes_to_hex(self, data: bytes) -> str:
        return ''.join('%02x' % b for b in data)

    def __escape_escapable(self, s: str) -> str:
        """Escape CLI escapable characters in the given string.
        """
        escapable_chars = '\\ \t\r\n'
        for char in escapable_chars:
            s = s.replace(char, '\\%s' % char)
        return s

    def __txt_to_hex(self, txt: Dict[str, Union[str, bytes, bool]]) -> str:
        txt_bin = b''
        for k, v in txt.items():
            assert '=' not in k, 'TXT key must not contain `=`'

            if isinstance(v, str):
                entry = f'{k}={v}'.encode('utf8')
            elif isinstance(v, bytes):
                entry = f'{k}='.encode('utf8') + v
            else:
                assert v is True, 'TXT val must be str or bytes or True'
                entry = k.encode('utf8')

            assert len(entry) <= 255, 'TXT entry is too long'

            txt_bin += bytes([len(entry)])
            txt_bin += entry

        return ''.join('%02x' % b for b in txt_bin)

    def __get_optional_int_argument(self, arg_name: str, arg_value: Optional[int] = None):
        return arg_name + f' {arg_value} ' if arg_value is not None else ''

    def __get_optional_bool_argument(self, arg_name: str, arg_value: Optional[bool] = None):
        return arg_name + ' ' if arg_value is not None and arg_value else ''


def connect_cli_sim(executable: str, nodeid: int, simulator: Optional[Simulator]) -> OTCI:
    cli_handler = connectors.OtCliSim(executable, nodeid, simulator=simulator)
    cmd_handler = OtCliCommandRunner(cli_handler)
    return OTCI(cmd_handler)


def connect_cli_serial(dev: str, baudrate: int = 115200) -> OTCI:
    cli_handler = connectors.OtCliSerial(dev, baudrate)
    cmd_handler = OtCliCommandRunner(cli_handler)
    return OTCI(cmd_handler)


def connect_ncp_sim(executable: str, nodeid: int, simulator: Optional[Simulator]) -> OTCI:
    ncp_handler = connectors.OtNcpSim(executable, nodeid, simulator=simulator)
    cmd_handler = OtCliCommandRunner(ncp_handler, is_spinel_cli=True)
    return OTCI(cmd_handler)


def connect_otbr_ssh(host: str,
                     port: int = 22,
                     username: str = 'pi',
                     password: str = 'raspberry',
                     sudo: bool = True) -> OTCI:
    cmd_handler = OtbrSshCommandRunner(host, port, username, password, sudo=sudo)
    return OTCI(cmd_handler)


def connect_otbr_adb_tcp(host: str, port: int = 5555, adb_key: Optional[str] = None) -> OTCI:
    cmd_handler = OtbrAdbTcpCommandRunner(host, port, adb_key)
    return OTCI(cmd_handler)


def connect_otbr_adb_usb(serial: str, adb_key: Optional[str] = None) -> OTCI:
    cmd_handler = OtbrAdbUsbCommandRunner(serial, adb_key)
    return OTCI(cmd_handler)


def connect_cmd_handler(cmd_handler: OTCommandHandler) -> OTCI:
    return OTCI(cmd_handler)
