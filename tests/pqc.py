import hashlib
import hmac
import time
import unittest
from unittest.mock import patch

import RNS
from RNS.PQ import (
    FragmentAssembler, PQAnnounceTransfer, PQFragment, PQSessionManager,
    fragment_record, fragment_payload_size, RECORD_SESSION_DATA,
    FRAGMENT_RETRANSMIT_FLAG,
)


class TestPQFragments(unittest.TestCase):
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
                                 fragment.total_length, fragment.payload, flags=0x40)
        with self.assertRaises(ValueError):
            assembler.add(conflicting)

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

    def test_limits_reject_before_allocation(self):
        data = bytearray(PQFragment(1, hashlib.sha256(b"x").digest(), 0, 1, 1, b"x").pack())
        data[0] = ord("X")
        with self.assertRaises(ValueError):
            PQFragment.unpack(data)
        self.assertGreater(fragment_payload_size(), 0)


if __name__ == "__main__":
    unittest.main()
