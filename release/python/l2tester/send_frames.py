import time
import logging

from .interface import get_interface
from .packet import l2_frame_from_to
from .l2tester import SendAndCheck

from scapy.layers.l2 import Ether

logger = logging.getLogger("Send Frames")

# If logger name Bandwidth has no handlers, add simple one:
if not logger.handlers:
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())


## Mapping printing ################################################################################

class FrameCounter(dict):
    """ Convert a list of frames into a dictionary mapping { frame : num_occurences }.
    """

    def __init__(self, frame_list):
        """ Count frames occurrences in list, updating this dictionary.
        @param frame_list    List of frames to be analyzed.
        """

        dict.__init__(self)
        for frame in frame_list:
            raw_frame = str(frame)
            self[raw_frame] = self.get(raw_frame, 0) + 1


def frame_mapping_to_str(mapping, raw=False):
    """ Return a representable string for the mapping { iface : [ frame_list ], ... }
    @param mapping           Dictionary of interfaces to frame list.
    """
    if raw:
        return '\n'.join([
            " {0:<9} : {1}".format(iface, '\n           : '.join([
                "{0} ({1} bytes) [x{2}]".format(str(frame).encode("HEX"),
                                                len(frame) + 4, count)  # Add 4 bytes of FCS
                for frame, count in FrameCounter(frames).iteritems()]))
            for iface, frames in mapping.iteritems()])
    else:
        return '\n'.join([
            " {0:<9} : {1}".format(iface, '\n           : '.join([
                "{0} ({1} bytes) [x{2}]".format(Ether(frame).summary(),
                                                len(frame) + 4, count)  # Add 4 bytes of FCS
                for frame, count in FrameCounter(frames).iteritems()]))
            for iface, frames in mapping.iteritems()])


## Send frames #####################################################################################

def send_frame(frame_mapping):
    """ Send multiples frames from multiples interfaces.
    @param frame_mapping     Dictionary containing a map of { iface : [ frame_list ], ... }
    """
    if type(frame_mapping) != dict:
        raise TypeError("Expected dictionary for frame_mapping, got " +
                        str(type(frame_mapping)) + ".")

    logger.info("Sending frames:\n%s", frame_mapping_to_str(frame_mapping))
    for if_name, frames in frame_mapping.iteritems():
        iface = get_interface(if_name)
        for frame in frames:
            iface.send(frame)
            time.sleep(0.001)


## Send And Check frames ###########################################################################

def send_and_check(send_frames, expected_frames, ignore_unexpected_frames=False, timeout=1.0,
                   do_not_log_error_on_error=False, print_raw_packets=False):
    """ Send frames from PC interfaces and monitor interfaces for received frames.
    @param send_frames                Dictionary containing a map of { iface : [ frame_list ], ... }
    @param expected_frames            Dictionary containing a map of { iface : [ frame_list ], ... }
    @param ignore_unexpected_frames   Inform if unexpected frames must be ignored or not.
    @param timeout                    Time spent for interface monitoring.
    @param do_not_log_error_on_error  Do not log as error whenever an error occurs.
    @param print_raw_packets          Log packets as raw hex string

    This function is intended to do a frame-by-frame analysis with full frame match.
    The first parameter specify what frames should be sent, and from which interfaces,
    the second which interfaces should be monitored, and what frames should be expected.
    To monitor an interface that should not receive a frame, pass to it an empty list.

    Ex:
    frameA = Ether(src='10:00:01:02:03:04', dst='FF:FF:FF:FF:FF:FF') / Dot1Q(vlan=10) /
             Raw(load=100*'\0')
    frameB = Ether(src='10:00:01:02:03:04', dst='FF:FF:FF:FF:FF:FF') / Dot1Q(vlan=20) /
             Raw(load=100*'\0')

    send_and_check(
        send_frames = {
            'eth0' : 10 * [frameA] + 3 * [frameB] },
        expected_frames = {
            'eth0' : [],
            'eth1' : 10 * [frameA]
            'eth2  : 13 * [frameB] })

    The code above will send 10 frameA and 3 frameB from eth0. Meanwhile, it will monitor interfaces
    eth0, eth1 and eth2. It will assure no frames were received in eth0, that 10 frameA were
    received in eth1 and 13 frameB in eth2.
    """

    send_checker = SendAndCheck(send_frames, expected_frames, int(timeout * 1000))
    logger.info("Sending frames:\n%s", frame_mapping_to_str(send_frames, raw=print_raw_packets))
    send_checker.run()

    missed_frames = send_checker.get_missed_frames()
    received_frames = send_checker.get_received_frames()
    unexpected_frames = send_checker.get_unexpected_frames()

    err_msg = ""

    if not missed_frames:
        if not received_frames:
            logger.info("No frames received, as expected.")
        else:
            logger.info("All expected frames received:\n%s",
                        frame_mapping_to_str(received_frames, raw=print_raw_packets))
    else:
        num_received = reduce(lambda total, list: total+len(list), received_frames.values(), 0)
        num_missed = reduce(lambda total, list: total+len(list), missed_frames.values(), 0)
        num_expected = num_received + num_missed
        if received_frames:
            logger.info("Received %d of %d expected frames:\n%s", num_received,
                        num_expected, frame_mapping_to_str(received_frames, raw=print_raw_packets))
        err_msg_missed = "Missed {0} expected frames:\n{1}".format(
            num_missed, frame_mapping_to_str(missed_frames, raw=print_raw_packets))
        if do_not_log_error_on_error:
            logger.info(err_msg_missed)
        else:
            logger.error(err_msg_missed)
        err_msg = "{0}{1}\n".format(err_msg, err_msg_missed)

    if (unexpected_frames and not ignore_unexpected_frames):
        num_unexpected = reduce(lambda total, list: total+len(list), unexpected_frames.values(), 0)
        err_msg_unexpected = "Received {0} unexpected frames:\n{1}".format(
            num_unexpected, frame_mapping_to_str(unexpected_frames, raw=print_raw_packets))
        if do_not_log_error_on_error:
            logger.info(err_msg_unexpected)
        else:
            logger.error(err_msg_unexpected)
        err_msg = "{0}{1}\n".format(err_msg, err_msg_unexpected)

    if not err_msg == "":
        raise AssertionError(err_msg)


## Send from one interface to another ##############################################################

def send_from_to(if_src, if_dst, *vlans):
    """ Send a frame using interfaces MACs.
    @param if_src  Name of the source interface.
    @param if_dst  Name of the destination interface.
                   It can also be:
                   * 'broadcast' to use 'FF:FF:FF:FF:FF:FF' as destination MAC.
                   * 'multicast' to use '01:00:10:20:30:44' as destination MAC.
    @param *vlans  Variable number of integer params used as VLAN Tags.
    """
    frame = l2_frame_from_to(if_src, if_dst, vlans)
    get_interface(if_src).send(frame)
