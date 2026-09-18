import hashlib
from types import SimpleNamespace
import hmac
import time
import tempfile
import unittest
from unittest.mock import patch

from RNS.Channel import MessageBase
import RNS
from RNS.PQ import (
    FragmentAssembler, PQAnnounceTransfer, PQFragment, PQSessionManager,
    fragment_record, fragment_payload_size, RECORD_LINK, RECORD_SESSION_DATA,
    RECORD_SESSION_REQUEST,
    FRAGMENT_RETRANSMIT_FLAG,
)

class TestPQFragments(unittest.TestCase):
    def test_pq_handshake_teardown_without_key(self):
        link = object.__new__(RNS.Link)
        link.status = RNS.Link.PQ_HANDSHAKE
        link.derived_key = None
        link.initiator = True

        with patch.object(link, "_Link__teardown_packet") as send_close, \
                patch.object(link, "link_closed") as closed:
            link.teardown()

        self.assertEqual(link.status, RNS.Link.CLOSED)
        self.assertEqual(link.teardown_reason, RNS.Link.INITIATOR_CLOSED)
        send_close.assert_not_called()
        closed.assert_called_once_with()

    def test_pq_timeout_reason_is_defined(self):
        self.assertEqual(RNS.Link.TIMEOUT, 0x01)

    def test_pq_link_fragment_routes_before_validation(self):
        class InterfaceStub:
            online = True
            reports_phy_stats = False
            r_stat_rssi = None
            r_stat_snr = None
            r_stat_q = None

            def protocol_violation(self, reason):
                raise AssertionError(reason)

        transport = RNS.Transport
        source = InterfaceStub()
        target = InterfaceStub()
        link_hash = b"L" * (RNS.Identity.TRUNCATED_HASHLENGTH // 8)
        destination = SimpleNamespace(
            hash=link_hash, type=RNS.Destination.LINK, mtu=RNS.Reticulum.MTU)
        from RNS.PQ import RECORD_LINK, fragment_record
        fragment = fragment_record(RECORD_LINK, b"PQ handshake fragment")[0]
        packet = RNS.Packet(
            destination, fragment.pack(),
            packet_type=RNS.Packet.PROOF, context=RNS.Packet.PQ_FRAGMENT,
            create_receipt=False,
        )
        packet.destination_type = RNS.Destination.LINK
        packet.transport_type = RNS.Transport.BROADCAST
        packet.pack()
        packet.receiving_interface = source
        packet.hops = 1
        link_entry = [
            time.time(), None, target, 1, source, 1, b"D" * len(link_hash),
            False, time.time() + 30,
        ]
        transmitted = []

        with patch.object(transport, "link_table", {link_hash: link_entry}), \
                patch.object(transport, "local_client_interfaces", []), \
                patch.object(transport, "reverse_table", {}), \
                patch.object(transport, "local_hops_delta", 0), \
                patch.object(transport, "packet_hashlist", []), \
                patch.object(transport, "packet_hashlist_prev", []), \
                patch.object(transport, "add_packet_hash"), \
                patch.object(transport, "transmit",
                             side_effect=lambda interface, raw:
                             transmitted.append((interface, raw))), \
                patch.object(transport, "interface_to_shared_instance",
                             staticmethod(lambda interface: False)), \
                patch.object(RNS.Reticulum, "transport_enabled",
                             staticmethod(lambda: True)):
            transport._inbound(packet)

        expected_raw = packet.raw[0:1] + b"\x01" + packet.raw[2:]
        self.assertEqual(transmitted, [(target, expected_raw)])
        self.assertTrue(link_entry[7])

    def test_fragmented_announce_enters_transport_inbound(self):
        class IdentityStub:
            crypto_mode = RNS.Identity.CRYPTO_PQ

        class DestinationStub:
            type = RNS.Destination.SINGLE
            hash = b"X" * (RNS.Reticulum.TRUNCATED_HASHLENGTH // 8)
            identity = IdentityStub()

        class InterfaceStub:
            HW_MTU = RNS.Reticulum.MTU
            ifac_size = 0
            def should_ingress_limit(self): return False
            def received_announce(self, size): pass

        inbound = unittest.mock.Mock()
        transport = RNS.Transport
        with patch.object(transport, "ready", True), \
             patch.object(transport, "identity", object()), \
             patch.object(transport, "pq_fragment_assembler", FragmentAssembler()), \
             patch.object(transport, "packet_filter", staticmethod(lambda packet: True)), \
             patch.object(transport, "USE_INBOUND_QUEUE", False), \
             patch.object(transport, "pr_destination_hash",
                          b"Y" * (RNS.Identity.TRUNCATED_HASHLENGTH // 8)), \
             patch.object(transport, "_inbound", staticmethod(inbound)), \
             patch.object(RNS.Identity, "validate_announce",
                          staticmethod(lambda *args, **kwargs: True)):
            transfer = PQAnnounceTransfer(DestinationStub(), b"a" * 2000, RNS.Packet.NONE)
            interface = InterfaceStub()
            for packet in transfer.packets:
                transport.preprocess_inbound(packet.raw, interface=interface)

        inbound.assert_called_once()
        logical_packet = inbound.call_args.args[0]
        self.assertEqual(logical_packet.data, b"a" * 2000)
        self.assertEqual(len(logical_packet.fragment_set), len(transfer.packets))
        self.assertEqual(logical_packet.packet_hash, logical_packet.get_hash())
        cached_packet = RNS.Packet(None, logical_packet.raw)
        self.assertTrue(cached_packet.unpack())
        self.assertEqual(cached_packet.data, logical_packet.data)

        class TransportIdentityStub:
            hash = b"T" * (RNS.Reticulum.TRUNCATED_HASHLENGTH // 8)

        with patch.object(transport, "identity", TransportIdentityStub()), \
             patch.object(RNS.Identity, "parse_announce",
                          staticmethod(lambda *args, **kwargs: {
                              "mode": RNS.Identity.CRYPTO_PQ,
                          })):
            retransmitted = transport._announce_retransmit_packets(
                cached_packet, DestinationStub(), RNS.Packet.PATH_RESPONSE,
                None, logical_packet.hops)

        self.assertGreater(len(retransmitted), 1)
        self.assertTrue(all(packet.context == RNS.Packet.PQ_FRAGMENT
                            for packet in retransmitted))
        assembler = FragmentAssembler()
        recovered = None
        for packet in retransmitted:
            recovered = assembler.add(PQFragment.unpack(packet.data))
        self.assertEqual(recovered, logical_packet.data)

    def test_announce_transfer_keeps_one_fragmented_representation(self):
        class IdentityStub:
            crypto_mode = RNS.Identity.CRYPTO_PQ

        class DestinationStub:
            type = RNS.Destination.SINGLE
            hash = b"\x01" * (RNS.Reticulum.TRUNCATED_HASHLENGTH // 8)
            identity = IdentityStub()

        transfer = PQAnnounceTransfer(DestinationStub(), b"announce", RNS.Packet.NONE)
        self.assertEqual(transfer.announce_data, b"announce")
        self.assertEqual(len(transfer.packets), 1)
        self.assertTrue(all(packet.context == RNS.Packet.PQ_FRAGMENT
                            for packet in transfer.packets))
        self.assertTrue(all(PQFragment.unpack(packet.data).flags & 0x60 == 0x20
                            for packet in transfer.packets))

    def test_frames_fit_both_header_budgets(self):
        payload = b"pqc" * 5000
        for header_type, header_size in (
            (RNS.Packet.HEADER_1, RNS.Reticulum.HEADER_MINSIZE),
            (RNS.Packet.HEADER_2, RNS.Reticulum.HEADER_MAXSIZE),
        ):
            fragments = fragment_record(1, payload, header_type=header_type)
            self.assertLessEqual(len(fragments), 64)
            for fragment in fragments:
                self.assertLessEqual(header_size + len(fragment.pack()), RNS.Reticulum.MTU)
                self.assertLessEqual(len(fragment.pack()), RNS.Reticulum.MTU - header_size)

    def test_out_of_order_duplicate_and_digest(self):
        payload = b"logical-pq-record" * 100
        fragments = fragment_record(1, payload)
        assembler = FragmentAssembler()
        self.assertIsNone(assembler.add(fragments[-1]))
        self.assertIsNone(assembler.add(fragments[-1]))
        result = None
        for fragment in fragments[:-1]:
            result = assembler.add(fragment)
        self.assertEqual(result, payload)
        self.assertEqual(len(assembler), 0)

    def test_retransmitted_announce_fragments_complete_partial_record(self):
        payload = b"retransmit-me" * 250
        initial = fragment_record(1, payload, flags=0x20)
        retry = fragment_record(1, payload,
                                flags=0x20 | FRAGMENT_RETRANSMIT_FLAG)
        assembler = FragmentAssembler()
        self.assertNotEqual(initial[0].pack(), retry[0].pack())

        for fragment in initial[:-1]:
            self.assertIsNone(assembler.add(fragment))

        result = None
        for fragment in retry:
            result = assembler.add(fragment)

        self.assertEqual(result, payload)

    def test_pq_fragments_use_distinct_announce_queue_keys(self):
        class IdentityStub:
            crypto_mode = RNS.Identity.CRYPTO_PQ

        class DestinationStub:
            type = RNS.Destination.SINGLE
            hash = b"\x03" * (RNS.Reticulum.TRUNCATED_HASHLENGTH // 8)
            identity = IdentityStub()

        transfer = PQAnnounceTransfer(DestinationStub(), b"q" * 2000, RNS.Packet.NONE)
        keys = [RNS.Transport._announce_queue_key(packet) for packet in transfer.packets]

        self.assertEqual(len(keys), len(set(keys)))

    def test_conflicting_duplicate_and_tamper_are_rejected(self):
        payload = b"record" * 100
        fragment = fragment_record(1, payload)[0]
        assembler = FragmentAssembler()
        assembler.add(fragment)
        conflicting = PQFragment(fragment.record_kind, fragment.record_id,
                                 fragment.fragment_index, fragment.fragment_count,
                                 fragment.total_length, fragment.payload + b"!")
        with self.assertRaises(ValueError):
            assembler.add(conflicting)

        tampered = fragment_record(1, payload)
        tampered_raw = bytearray(tampered[-1].pack())
        tampered_raw[-1] ^= 1
        digest_assembler = FragmentAssembler()
        for item in tampered[:-1]:
            digest_assembler.add(item)
        with self.assertRaises(ValueError):
            digest_assembler.add(PQFragment.unpack(tampered_raw))
    def test_manifest_flags_must_match(self):
        payload = b"flagged-record" * 100
        fragment = fragment_record(1, payload, flags=0x20)[0]
        assembler = FragmentAssembler()
        assembler.add(fragment)
        conflicting = PQFragment(fragment.record_kind, fragment.record_id,
                                 fragment.fragment_index, fragment.fragment_count,
                                 fragment.total_length, fragment.payload, flags=0x22)
        with self.assertRaises(ValueError):
            assembler.add(conflicting)
    def test_removed_announce_mode_is_rejected(self):
        fragment = fragment_record(1, b"announce", flags=0x40)[0]
        packet = type("Packet", (), {
            "data": fragment.pack(), "raw": b"", "destination_hash": b"D" * 16,
            "destination_type": RNS.Destination.SINGLE,
            "header_type": RNS.Packet.HEADER_1, "transport_type": RNS.Transport.BROADCAST,
            "transport_id": None, "hops": 0, "receiving_interface": None,
            "rssi": None, "snr": None, "q": None,
        })()
        with self.assertRaises(ValueError):
            RNS.Transport._reassemble_announce(packet)

    @unittest.skipUnless(RNS.Cryptography.pq_available(), "liboqs not available")
    def test_removed_session_mode_is_rejected(self):
        old_mode = RNS.Identity.CRYPTO_MODE
        try:
            RNS.Identity.set_crypto_mode(RNS.Identity.CRYPTO_PQ)
            identity = RNS.Identity()
            destination = type("Destination", (), {
                "identity": identity, "hash": b"D" * 16,
            })()
            manager = PQSessionManager()
            _, request, _ = manager.create_request(destination, b"payload")
            request = bytearray(request)
            self.assertEqual(request[1], 0)
            request[1] = 1
            with self.assertRaises(ValueError):
                manager.accept_request(identity, destination.hash, request)
        finally:
            RNS.Identity.set_crypto_mode(old_mode)

    @unittest.skipUnless(RNS.Cryptography.pq_available(), "liboqs not available")
    def test_removed_link_mode_is_rejected(self):
        old_mode = RNS.Identity.CRYPTO_MODE
        try:
            RNS.Identity.set_crypto_mode(RNS.Identity.CRYPTO_PQ)
            identity = RNS.Identity()
            owner = type("Owner", (), {"identity": identity})()
            link = RNS.Link.__new__(RNS.Link)
            link.owner = owner
            link.destination = object()
            link.link_id = b"L" * 16
            from RNS.vendor import umsgpack
            request = {
                "type": "pq_request", "link_id": link.link_id,
                "mode": "hybrid",
            }
            self.assertFalse(link._handle_pq_handshake_request(
                umsgpack.packb(request)))
        finally:
            RNS.Identity.set_crypto_mode(old_mode)

    def test_removed_tunnel_mode_is_rejected(self):
        violation = unittest.mock.Mock()
        packet = type("Packet", (), {"receiving_interface": violation})()
        data = RNS.Transport.PQ_TUNNEL_MAGIC + b"\x02\x00\x00"
        RNS.Transport.tunnel_synthesize_handler(data, packet)
        violation.protocol_violation.assert_called_once()

    def test_session_data_requires_ack_and_preserves_logical_payload(self):
        manager = PQSessionManager()
        destination_hash = b"\x02" * 16
        session_id = b"\x03" * 8
        transcript = b"\x04" * 32
        key = b"\x05" * 32
        logical_payload = b"logical session payload"
        with manager._lock:
            manager.sessions[(destination_hash, session_id)] = {
                "key": key, "transcript": transcript,
                "logical_hash": RNS.Identity.full_hash(logical_payload),
                "logical_payload": logical_payload,
                "updated": time.monotonic(), "established": False,
                "data_sent": False, "data_received": False, "seen": set(),
            }
        with self.assertRaises(RuntimeError):
            manager.encrypt_data(destination_hash, session_id, logical_payload)
        ack = manager.ACK_HEADER.pack(
            manager.SESSION_VERSION, session_id, transcript,
            hmac.new(key, b"ACK"+transcript, hashlib.sha256).digest())
        self.assertTrue(manager.validate_ack(destination_hash, session_id, ack))
        fragments = manager.data_fragments_after_ack(destination_hash, session_id)
        self.assertTrue(fragments)
        data = b"".join(fragment.payload for fragment in fragments)
        self.assertEqual(manager.decrypt_data(destination_hash, data), logical_payload)
    def test_unknown_pq_session_fragment_remains_forwardable(self):
        fragment = PQFragment(
            1, hashlib.sha256(b"unknown-destination").digest(),
            0, 1, RECORD_SESSION_DATA, b"\x00" * 8)
        packet = type(
            "Packet", (), {
                "data": fragment.pack(),
                "destination_hash": b"\x01" * (RNS.Reticulum.TRUNCATED_HASHLENGTH // 8),
                "destination_type": RNS.Destination.SINGLE,
            })()
        self.assertFalse(RNS.Transport._handle_pq_session_fragment(packet))
    def test_unknown_pq_session_request_remains_forwardable(self):
        fragments = fragment_record(
            RECORD_SESSION_REQUEST, b"unknown-destination-request" * 100)
        packet = type(
            "Packet", (), {
                "data": fragments[0].pack(),
                "destination_hash": b"\x01" * (RNS.Reticulum.TRUNCATED_HASHLENGTH // 8),
                "destination_type": RNS.Destination.SINGLE,
            })()
        self.assertFalse(RNS.Transport._handle_pq_session_fragment(packet))
    def test_pq_proof_fragment_uses_reverse_route(self):
        from RNS.Packet import ProofDestination
        source = SimpleNamespace()
        target = SimpleNamespace()
        proof_hash = b"\x02" * (RNS.Reticulum.TRUNCATED_HASHLENGTH // 8)
        packet = RNS.Packet(
            ProofDestination(SimpleNamespace(
                truncated_packet_hash=proof_hash)),
            b"pq proof",
            packet_type=RNS.Packet.PROOF,
            context=RNS.Packet.PQ_FRAGMENT,
            attached_interface=target,
            create_receipt=False,
        )
        packet.pack()
        transmitted = []
        with patch.object(RNS.Transport, "reverse_table", {
                proof_hash: [source, target, time.time()]}), \
                patch.object(RNS.Transport, "transmit",
                             side_effect=lambda interface, raw:
                             transmitted.append((interface, raw))):
            self.assertTrue(RNS.Transport._outbound(packet))
        self.assertEqual(transmitted, [(source, packet.raw)])



    @unittest.skipUnless(RNS.Cryptography.pq_available(), "liboqs not available")
    def test_pq_tunnel_synthesis_uses_fragmented_signed_record(self):
        old_mode = RNS.Identity.CRYPTO_MODE
        old_identity = RNS.Transport.identity
        old_assembler = RNS.Transport.pq_fragment_assembler
        captured = []

        class Interface:
            wants_tunnel = True

            def get_hash(self):
                return b"\x42" * (RNS.Identity.HASHLENGTH // 8)

            def __str__(self):
                return "PQ tunnel test interface"

        interface = Interface()
        try:
            RNS.Identity.set_crypto_mode(RNS.Identity.CRYPTO_PQ)
            RNS.Transport.identity = RNS.Identity()

            def capture(packet):
                captured.append(packet)
                return True

            with patch.object(RNS.Transport, "outbound", side_effect=capture), \
                    patch.object(RNS.Transport, "handle_tunnel") as handle_tunnel:
                RNS.Transport.synthesize_tunnel(interface)
                self.assertFalse(interface.wants_tunnel)
                self.assertGreater(len(captured), 1)
                tunnel_assembler = FragmentAssembler()
                tunnel_data = None
                for sent in captured:
                    packet = RNS.Packet(None, sent.raw)
                    self.assertTrue(packet.unpack())
                    tunnel_data = tunnel_assembler.add(PQFragment.unpack(packet.data))
                self.assertIsNotNone(tunnel_data)
                self.assertEqual(tunnel_data[len(RNS.Transport.PQ_TUNNEL_MAGIC)], 1)
                for sent in captured:
                    packet = RNS.Packet(None, sent.raw)
                    self.assertTrue(packet.unpack())
                    packet.receiving_interface = interface
                    self.assertTrue(RNS.Transport._handle_pq_session_fragment(packet))
                handle_tunnel.assert_called_once()
        finally:
            RNS.Transport.identity = old_identity
            RNS.Transport.pq_fragment_assembler = old_assembler
            RNS.Identity.set_crypto_mode(old_mode)


    @unittest.skipUnless(RNS.Cryptography.pq_available(), "liboqs not available")
    def test_pq_destination_roundtrip_delivers_and_proves_logical_packet(self):
        old_mode = RNS.Identity.CRYPTO_MODE
        old_owner = getattr(RNS.Transport, "owner", None)
        old_manager = RNS.Transport.pq_session_manager
        old_assembler = RNS.Transport.pq_session_assembler
        old_destinations = RNS.Transport.destinations_map
        old_receipts = RNS.Transport.receipts[:]
        captured = []
        received = []
        interface = object()
        receiver_destination = None

        try:
            RNS.Transport.owner = type(
                "Owner", (), {"is_connected_to_shared_instance": False})()
            RNS.Identity.set_crypto_mode(RNS.Identity.CRYPTO_PQ)
            receiver_identity = RNS.Identity()
            receiver_destination = RNS.Destination(
                receiver_identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                "tests", "pq", "receiver")
            def receive(data, packet):
                self.assertIs(packet.destination, receiver_destination)
                packet.prove()
                received.append(data)

            receiver_destination.set_packet_callback(receive)
            sender_identity = RNS.Identity(create_keys=False)
            sender_identity.load_public_key(receiver_identity.serialize_public_key())
            sender_destination = RNS.Destination(
                sender_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                "tests", "pq", "receiver")
            payload = b"lxmf-like PQ destination payload"

            def capture(packet):
                captured.append(packet)
                return True

            sender_manager = PQSessionManager()
            receiver_manager = PQSessionManager()
            RNS.Transport.pq_session_manager = sender_manager
            RNS.Transport.pq_session_assembler = None

            reticulum = type(
                "Reticulum", (), {"get_first_hop_timeout": lambda self, destination_hash: 1.0})()
            with patch.object(RNS.Reticulum, "get_instance", return_value=reticulum), \
                    patch.object(RNS.Transport, "outbound", side_effect=capture):
                logical_packet = RNS.Packet(sender_destination, payload)
                receipt = logical_packet.send()
                self.assertIsNot(False, receipt)
                self.assertGreater(len(captured), 1)

                RNS.Transport.pq_session_manager = receiver_manager
                RNS.Transport.pq_session_assembler = None
                request_packets = list(captured)
                captured.clear()
                for sent in request_packets:
                    packet = RNS.Packet(None, sent.raw)
                    self.assertTrue(packet.unpack())
                    packet.receiving_interface = interface
                    RNS.Transport._handle_pq_session_fragment(packet)
                ack_packets = list(captured)
                self.assertTrue(ack_packets)

                RNS.Transport.pq_session_manager = sender_manager
                RNS.Transport.pq_session_assembler = None
                captured.clear()
                for sent in ack_packets:
                    packet = RNS.Packet(None, sent.raw)
                    self.assertTrue(packet.unpack())
                    packet.receiving_interface = interface
                    RNS.Transport._handle_pq_session_fragment(packet)
                data_packets = list(captured)
                self.assertTrue(data_packets)

                RNS.Transport.pq_session_manager = receiver_manager
                RNS.Transport.pq_session_assembler = None
                captured.clear()
                for sent in data_packets:
                    packet = RNS.Packet(None, sent.raw)
                    self.assertTrue(packet.unpack())
                    packet.receiving_interface = interface
                    RNS.Transport._handle_pq_session_fragment(packet)
                self.assertEqual(received, [payload])
                proof_packets = list(captured)
                self.assertTrue(proof_packets)

                RNS.Transport.pq_session_manager = sender_manager
                RNS.Transport.pq_session_assembler = None
                for sent in proof_packets:
                    packet = RNS.Packet(None, sent.raw)
                    self.assertTrue(packet.unpack())
                    packet.receiving_interface = interface
                    RNS.Transport._handle_pq_session_fragment(packet)
                self.assertEqual(receipt.status, RNS.PacketReceipt.DELIVERED)
        finally:
            if receiver_destination is not None:
                RNS.Transport.deregister_destination(receiver_destination)
            RNS.Transport.pq_session_manager = old_manager
            RNS.Transport.pq_session_assembler = old_assembler
            RNS.Transport.receipts[:] = old_receipts
            RNS.Transport.destinations_map = old_destinations
            if old_owner is None:
                del RNS.Transport.owner
            else:
                RNS.Transport.owner = old_owner
            RNS.Identity.set_crypto_mode(old_mode)

    @unittest.skipUnless(RNS.Cryptography.pq_available(), "liboqs not available")
    def test_pq_link_packet_roundtrip(self):
        old_mode = RNS.Identity.CRYPTO_MODE
        old_owner = getattr(RNS.Transport, "owner", None)
        old_receipts = RNS.Transport.receipts[:]
        captured = []
        interface = object()
        receiver_destination = None
        received = []
        receiver_established = []

        try:
            RNS.Transport.owner = type(
                "TransportOwner", (), {"is_connected_to_shared_instance": False})()
            RNS.Identity.set_crypto_mode(RNS.Identity.CRYPTO_PQ)
            receiver_identity = RNS.Identity()
            receiver_destination = RNS.Destination(
                receiver_identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                "tests", "pq", "link")
            receiver_destination.set_packet_callback(
                lambda data, packet: received.append(data))

            sender_identity = RNS.Identity(create_keys=False)
            sender_identity.load_public_key(receiver_identity.serialize_public_key())
            sender_destination = RNS.Destination(
                sender_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                "tests", "pq", "link")

            callbacks = type(
                "Callbacks", (), {
                    "link_established": None,
                    "link_closed": None,
                    "packet": None,
                    "resource": None,
                    "resource_started": None,
                    "resource_concluded": None,
                    "remote_identified": None,
                })()
            callbacks.link_established = lambda link: receiver_established.append(link)
            owner = type("Owner", (), {
                "identity": receiver_identity, "callbacks": callbacks})()
            RNS.Transport.owner = owner

            reticulum = type(
                "Reticulum", (), {
                    "get_first_hop_timeout": lambda self, destination_hash: 1.0,
                    "get_packet_rssi": lambda self, packet_hash: None,
                    "get_packet_snr": lambda self, packet_hash: None,
                    "get_packet_q": lambda self, packet_hash: None,
                })()

            def capture(packet):
                captured.append(packet)
                if (packet.context != RNS.Packet.PQ_FRAGMENT and
                        packet.create_receipt and packet.receipt is None):
                    packet.receipt = RNS.PacketReceipt(packet)
                    RNS.Transport.receipts.append(packet.receipt)
                return True
            def unpack(sent):
                packet = RNS.Packet(None, sent.raw)
                self.assertTrue(packet.unpack())
                packet.receiving_interface = interface
                return packet
            with patch.object(RNS.Reticulum, "get_instance", return_value=reticulum), \
                    patch.object(RNS.Transport, "hops_to", return_value=1), \
                    patch.object(RNS.Transport, "next_hop_interface_hw_mtu", return_value=None), \
                    patch.object(RNS.Transport, "register_link"), \
                    patch.object(RNS.Transport, "activate_link"), \
                    patch.object(RNS.Link, "start_watchdog"), \
                    patch.object(RNS.Transport, "outbound", side_effect=capture), \
                    patch.object(RNS.Reticulum, "link_mtu_discovery", return_value=False):
                initiator = RNS.Link(sender_destination)
                request = unpack(captured.pop(0))
                request.destination = receiver_destination
                receiver = RNS.Link.validate_request(owner, request.data, request)
                self.assertIsNotNone(receiver)
                receiver.set_packet_callback(
                    lambda data, packet: received.append(data))

                identity_proof = [unpack(sent) for sent in captured]
                captured.clear()
                identity_proof_results = [
                    initiator.validate_proof(packet) for packet in identity_proof]
                self.assertTrue(any(identity_proof_results))

                pq_requests = [unpack(sent) for sent in captured]
                captured.clear()
                self.assertTrue(pq_requests)
                from RNS.vendor import umsgpack
                request_assembler = FragmentAssembler()
                request_payload = None
                for packet in pq_requests:
                    request_payload = request_assembler.add(PQFragment.unpack(packet.data))
                request_data = umsgpack.unpackb(request_payload)
                self.assertEqual(request_data["mode"], "pq")
                self.assertEqual(PQSessionManager.SESSION_VERSION, 1)
                transcript = (initiator.link_id + initiator.pub_bytes +
                              initiator.peer_pub_bytes + request_data["kem"] + b"\x00")
                pq_shared = receiver_identity.pq_prv.decapsulate(request_data["kem"])
                expected_key = RNS.Cryptography.hkdf(
                    length=64 if initiator.mode == RNS.Link.MODE_AES256_CBC else 32,
                    derive_from=pq_shared, salt=initiator.link_id,
                    context=b"RNS-PQ-LINK" + b"\x00" + hashlib.sha256(transcript).digest())
                for packet in pq_requests:
                    receiver.receive(packet)
                deadline = time.time() + 1.0
                while not receiver_established and time.time() < deadline:
                    time.sleep(0.01)
                self.assertEqual(receiver_established, [receiver])

                confirmations = [unpack(sent) for sent in captured]
                captured.clear()
                self.assertTrue(confirmations)
                for packet in confirmations:
                    self.assertTrue(initiator.validate_proof(packet))
                self.assertIsNone(initiator.shared_key)
                self.assertIsNone(receiver.shared_key)
                self.assertEqual(initiator.derived_key, expected_key)
                self.assertEqual(receiver.derived_key, expected_key)

                self.assertEqual(initiator.status, RNS.Link.ACTIVE)
                self.assertEqual(receiver.status, RNS.Link.ACTIVE)
                self.assertTrue(initiator.pq_confirmed)
                self.assertEqual(initiator.derived_key, receiver.derived_key)
                self.assertTrue(receiver.pq_confirmed)

                response_values = []
                receiver_destination.register_request_handler(
                    "/info",
                    response_generator=lambda path, data, request_id, link_id,
                    remote_identity, requested_at: b"pq-info-response",
                    allow=RNS.Destination.ALLOW_ALL,
                )
                receipt = initiator.request(
                    "/info",
                    response_callback=lambda item: response_values.append(
                        item.response
                    ),
                    failed_callback=lambda item: response_values.append(False),
                )
                self.assertNotEqual(receipt, False)
                request_packet = unpack(captured.pop(0))
                receiver.receive(request_packet)
                deadline = time.time() + 1.0
                while not captured and time.time() < deadline:
                    time.sleep(0.01)
                self.assertTrue(captured)
                response_packet = unpack(captured.pop(0))
                initiator.receive(response_packet)
                deadline = time.time() + 1.0
                while not response_values and time.time() < deadline:
                    time.sleep(0.01)
                self.assertEqual(response_values, [b"pq-info-response"])

                link_packet = RNS.Packet(
                    initiator, b"PQ link payload", create_receipt=False)
                link_packet.send()
                received_packet = unpack(captured.pop(0))
                receiver.receive(received_packet)
                deadline = time.time() + 1.0
                self.assertEqual(receiver.decrypt(received_packet.data),
                                 b"PQ link payload")
                while not received and time.time() < deadline:
                    time.sleep(0.01)
                self.assertEqual(received, [b"PQ link payload"])

                resource_data = b"PQ resource payload" * 32
                resource = RNS.Resource(
                    resource_data, initiator, advertise=False, auto_compress=False)
                encrypted_resource = b"".join(
                    part.data for part in resource.parts)
                decrypted_resource = receiver.decrypt(encrypted_resource)
                self.assertIsNotNone(decrypted_resource)
                self.assertEqual(decrypted_resource[4:], resource_data)
                receiver.set_resource_strategy(RNS.Link.ACCEPT_ALL)
                receiver_done = []
                receiver_data = []
                receiver.set_resource_concluded_callback(
                    lambda item: (receiver_done.append(item),
                                  receiver_data.append(item.data.read()))
                )
                resource_data = b"PQ resource transfer payload" * 64
                sender_done = []
                with tempfile.TemporaryDirectory() as resource_dir, \
                        patch.object(RNS.Reticulum, "resourcepath",
                                     resource_dir, create=True):
                    resource = RNS.Resource(
                        resource_data, initiator, auto_compress=False,
                        timeout=3, callback=lambda item: sender_done.append(item))
                    deadline = time.time() + 10.0
                    while resource.status not in (
                            RNS.Resource.COMPLETE, RNS.Resource.FAILED) and \
                            time.time() < deadline:
                        pending = list(captured)
                        captured.clear()
                        for sent in pending:
                            target = receiver if sent.destination is initiator else initiator
                            packet = unpack(sent)
                            packet.link = target
                            target.receive(packet)
                        time.sleep(0.01)
                    self.assertEqual(resource.status, RNS.Resource.COMPLETE)
                    self.assertTrue(receiver_done)
                    self.assertEqual(receiver_data[-1], resource_data)
                class ChannelMessage(MessageBase):
                    MSGTYPE = 0x1234
                    def __init__(self, data=b""):
                        self.data = data
                    def pack(self):
                        return self.data
                    def unpack(self, raw):
                        self.data = raw

                received_channel = []
                sender_channel = initiator.get_channel()
                receiver_channel = receiver.get_channel()
                sender_channel.register_message_type(ChannelMessage)
                receiver_channel.register_message_type(ChannelMessage)
                receiver_channel.add_message_handler(
                    lambda message: received_channel.append(message.data) or True)
                sender_channel.send(ChannelMessage(b"PQ channel payload"))
                for sent in list(captured):
                    if sent.context == RNS.Packet.CHANNEL and sent.destination is initiator:
                        channel_packet = unpack(sent)
                        channel_packet.link = receiver
                        receiver.receive(channel_packet)
                self.assertEqual(received_channel, [b"PQ channel payload"])
        finally:
            if receiver_destination is not None:
                RNS.Transport.deregister_destination(receiver_destination)
            RNS.Transport.receipts[:] = old_receipts
            if old_owner is None:
                del RNS.Transport.owner
            else:
                RNS.Transport.owner = old_owner
            RNS.Identity.set_crypto_mode(old_mode)

    def test_limits_reject_before_allocation(self):
        data = bytearray(PQFragment(1, hashlib.sha256(b"x").digest(), 0, 1, 1, b"x").pack())
        data[0] = ord("X")
        with self.assertRaises(ValueError):
            PQFragment.unpack(data)
        self.assertGreater(fragment_payload_size(), 0)


if __name__ == "__main__":
    unittest.main()
