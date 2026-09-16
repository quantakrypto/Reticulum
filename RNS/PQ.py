# Reticulum License
#
# Copyright (c) 2016-2025 Mark Qvist
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

from __future__ import annotations

import hashlib
import hmac
import struct
import threading
import time


FRAGMENT_MAGIC = b"RNSPQF1"
FRAGMENT_VERSION = 1
FRAGMENT_HEADER = struct.Struct("!7sBBB32sHHIH")
FRAGMENT_HEADER_SIZE = FRAGMENT_HEADER.size
FRAGMENT_MAX_RECORD = 16 * 1024
FRAGMENT_MAX_COUNT = 64
FRAGMENT_TIMEOUT = 60.0

RECORD_ANNOUNCE = 1
RECORD_TUNNEL = 2
RECORD_LINK = 3
RECORD_SESSION_REQUEST = 4
RECORD_SESSION_ACK = 5
RECORD_SESSION_DATA = 6
RECORD_PROOF = 7


class PQFragment:
    __slots__ = ("record_kind", "flags", "record_id", "fragment_index", "fragment_count",
                 "total_length", "payload")

    def __init__(self, record_kind, record_id, fragment_index, fragment_count, total_length,
                 payload, flags=0):
        if not isinstance(record_kind, int) or not 0 < record_kind < 256:
            raise ValueError("invalid PQ fragment record kind")
        if not isinstance(record_id, (bytes, bytearray)) or len(record_id) != 32:
            raise ValueError("record_id must be a SHA-256 digest")
        if not 0 <= fragment_index < fragment_count <= FRAGMENT_MAX_COUNT:
            raise ValueError("invalid PQ fragment index/count")
        if not 0 < total_length <= FRAGMENT_MAX_RECORD:
            raise ValueError("invalid PQ fragment total length")
        payload = bytes(payload)
        if len(payload) > 0xFFFF:
            raise ValueError("invalid PQ fragment payload length")
        if len(payload) == 0 and total_length > 0:
            raise ValueError("empty PQ fragment payload")
        self.record_kind = record_kind
        self.flags = flags & 0xFF
        self.record_id = bytes(record_id)
        self.fragment_index = fragment_index
        self.fragment_count = fragment_count
        self.total_length = total_length
        self.payload = payload

    def pack(self):
        return FRAGMENT_HEADER.pack(FRAGMENT_MAGIC, FRAGMENT_VERSION, self.record_kind,
                                    self.flags, self.record_id, self.fragment_index,
                                    self.fragment_count, self.total_length, len(self.payload)) + self.payload
    @classmethod
    def unpack(cls, data):
        data = bytes(data)
        if len(data) < FRAGMENT_HEADER_SIZE:
            raise ValueError("truncated PQ fragment")
        magic, version, kind, flags, record_id, index, count, total, payload_len = FRAGMENT_HEADER.unpack_from(data)
        if magic != FRAGMENT_MAGIC or version != FRAGMENT_VERSION:
            raise ValueError("unsupported PQ fragment envelope")
        if len(data) != FRAGMENT_HEADER_SIZE + payload_len:
            raise ValueError("PQ fragment payload length mismatch")
        if count == 0 or count > FRAGMENT_MAX_COUNT or index >= count:
            raise ValueError("invalid PQ fragment index/count")
        if total == 0 or total > FRAGMENT_MAX_RECORD:
            raise ValueError("invalid PQ fragment total length")
        if payload_len == 0:
            raise ValueError("empty PQ fragment payload")
        return cls(kind, record_id, index, count, total, data[FRAGMENT_HEADER_SIZE:], flags)


class FragmentAssembler:
    """Bounded, idempotent reassembly for authenticated logical records."""

    def __init__(self, max_records=256, max_bytes=4 * 1024 * 1024, timeout=FRAGMENT_TIMEOUT):
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.timeout = timeout
        self._records = {}
        self._completed = {}
        self._bytes = 0
        self._lock = threading.RLock()

    def _prune(self, now):
        expired = [key for key, entry in self._records.items()
                   if now - entry["updated"] > self.timeout]
        for key in expired:
            self._bytes -= self._records.pop(key)["bytes"]

    def add(self, fragment, now=None):
        if not isinstance(fragment, PQFragment):
            fragment = PQFragment.unpack(fragment)
        now = time.monotonic() if now is None else now
        key = (fragment.record_kind, fragment.record_id)
        with self._lock:
            self._prune(now)
            entry = self._records.get(key)
            if entry is None:
                if len(self._records) >= self.max_records:
                    raise MemoryError("PQ fragment record limit exceeded")
                if fragment.total_length > self.max_bytes:
                    raise MemoryError("PQ fragment record exceeds memory budget")
                entry = {"count": fragment.fragment_count, "total": fragment.total_length,
                         "flags": fragment.flags, "parts": {}, "bytes": 0, "updated": now}
                self._records[key] = entry
            elif (entry["count"], entry["total"], entry["flags"]) != (
                    fragment.fragment_count, fragment.total_length, fragment.flags):
                raise ValueError("conflicting PQ fragment manifest")

            existing = entry["parts"].get(fragment.fragment_index)
            if existing is not None:
                if existing != fragment.payload:
                    raise ValueError("conflicting duplicate PQ fragment")
                entry["updated"] = now
                return None
            if entry["bytes"] + len(fragment.payload) > entry["total"]:
                raise ValueError("PQ fragment record exceeds declared length")
            if self._bytes + len(fragment.payload) > self.max_bytes:
                raise MemoryError("PQ fragment memory budget exceeded")
            entry["parts"][fragment.fragment_index] = fragment.payload
            entry["bytes"] += len(fragment.payload)
            self._bytes += len(fragment.payload)
            entry["updated"] = now
            if len(entry["parts"]) != entry["count"]:
                return None

            assembled = b"".join(entry["parts"][index] for index in range(entry["count"]))
            if len(assembled) != entry["total"]:
                raise ValueError("PQ fragment record length mismatch")
            if hashlib.sha256(assembled).digest() != fragment.record_id:
                self._bytes -= entry["bytes"]
                del self._records[key]
                raise ValueError("PQ fragment record digest mismatch")

            completed = [PQFragment(fragment.record_kind, fragment.record_id, index,
                                     entry["count"], entry["total"],
                                     entry["parts"][index], entry["flags"])
                         for index in range(entry["count"])]
            while len(self._completed) >= self.max_records:
                self._completed.pop(next(iter(self._completed)))
            self._completed[key] = completed
            self._bytes -= entry["bytes"]
            del self._records[key]
            return assembled

    def take_completed(self, record_kind, record_id):
        with self._lock:
            return self._completed.pop((record_kind, bytes(record_id)), None)

    def manifest(self, record_kind, record_id):
        with self._lock:
            entry = self._records.get((record_kind, bytes(record_id)))
            if entry is None:
                return None
            return (entry["flags"], entry["count"], entry["total"],
                    tuple(sorted(entry["parts"])))

    def discard_expired(self, now=None):
        with self._lock:
            self._prune(time.monotonic() if now is None else now)

    def __len__(self):
        with self._lock:
            return len(self._records)


def fragment_payload_size(header_type=0, ifac_size=0, mtu=None):
    """Compute payload space from the actual packet/header budget."""
    import RNS
    if mtu is None:
        mtu = RNS.Reticulum.MTU
    header_size = RNS.Reticulum.HEADER_MAXSIZE if header_type else RNS.Reticulum.HEADER_MINSIZE
    capacity = mtu - header_size - int(ifac_size) - FRAGMENT_HEADER_SIZE
    if capacity <= 0:
        raise ValueError("interface MTU cannot carry a PQ fragment")
    return capacity


def fragment_record(record_kind, payload, flags=0, header_type=0, ifac_size=0, mtu=None):
    payload = bytes(payload)
    if not 0 < len(payload) <= FRAGMENT_MAX_RECORD:
        raise ValueError("invalid PQ logical record length")
    record_id = hashlib.sha256(payload).digest()
    capacity = fragment_payload_size(header_type=header_type, ifac_size=ifac_size, mtu=mtu)
    count = (len(payload) + capacity - 1) // capacity
    if count > FRAGMENT_MAX_COUNT:
        raise ValueError("PQ logical record requires too many fragments")
    return [PQFragment(record_kind, record_id, index, count, len(payload),
                       payload[index * capacity:(index + 1) * capacity], flags)
            for index in range(count)]


class PQAnnounceTransfer:
    """Prepared announce fragments; no partial record is sent or cached."""

    def __init__(self, destination, announce_data, context, context_flag=0,
                 attached_interface=None, header_type=0, ifac_size=0):
        import RNS
        self.destination = destination
        self.announce_data = bytes(announce_data)
        self.context = context
        self.context_flag = context_flag
        mode_flags = 1 if destination.identity.crypto_mode == RNS.Identity.CRYPTO_PQ else 2
        fragment_flags = (mode_flags << 5) | ((context & 0x0F) << 1) | (context_flag & 0x01)
        self.fragments = fragment_record(RECORD_ANNOUNCE, self.announce_data,
                                          flags=fragment_flags, header_type=header_type,
                                          ifac_size=ifac_size)
        self.packets = [RNS.Packet.from_fragment(destination, fragment.pack(),
                                                  packet_type=RNS.Packet.ANNOUNCE,
                                                  context=RNS.Packet.PQ_FRAGMENT,
                                                  header_type=header_type,
                                                  attached_interface=attached_interface,
                                                  context_flag=context_flag)
                        for fragment in self.fragments]

    def pack(self):
        return self.packets

    def send(self):
        for packet in self.packets:
            packet.send()
        return self.packets


class PQSessionManager:
    """Bounded state and transcript helpers for direct PQ logical packets."""

    REQUEST_HEADER = struct.Struct("!BB8s16s32s")
    ACK_HEADER = struct.Struct("!B8s32s32s")
    SESSION_VERSION = 1
    MAX_SESSIONS = 256
    SESSION_TTL = 600.0

    def __init__(self, max_sessions=MAX_SESSIONS, ttl=SESSION_TTL):
        self.max_sessions = max_sessions
        self.ttl = ttl
        self.sessions = {}
        self._lock = threading.RLock()

    @staticmethod
    def _derive(shared, destination_hash, session_id, transcript):
        import RNS
        return RNS.Cryptography.hkdf(length=32, derive_from=shared,
                                     salt=destination_hash,
                                     context=b"RNS-PQ-SESSION"+session_id+transcript)

    @staticmethod
    def _token(key):
        import RNS
        return RNS.Cryptography.Token(key)

    def _prune(self, now=None):
        now = time.monotonic() if now is None else now
        expired = [key for key, state in self.sessions.items()
                   if now - state["updated"] > self.ttl]
        for key in expired:
            self.sessions.pop(key, None)

    def destination_for_session(self, session_id):
        session_id = bytes(session_id)
        with self._lock:
            for (destination_hash, candidate_id), state in self.sessions.items():
                if candidate_id == session_id:
                    return destination_hash, state.get("destination")
        return None, None

    def create_request(self, destination, logical_payload):
        import os
        import RNS
        identity = destination.identity
        if identity is None or identity.crypto_mode == RNS.Identity.CRYPTO_LEGACY:
            raise ValueError("PQ session requires a PQ or hybrid destination")
        session_id = os.urandom(8)
        nonce = os.urandom(16)
        logical_payload = bytes(logical_payload)
        logical_hash = RNS.Identity.full_hash(logical_payload)
        ephemeral = b""
        shared_parts = []
        if identity.crypto_mode == RNS.Identity.CRYPTO_HYBRID:
            from RNS.Cryptography import X25519PrivateKey
            ephemeral_key = X25519PrivateKey.generate()
            ephemeral = ephemeral_key.public_key().public_bytes()
            shared_parts.append(ephemeral_key.exchange(identity.pub))
        ciphertext, pq_shared = identity.pq_pub.encapsulate()
        shared_parts.append(pq_shared)
        mode_byte = 1 if identity.crypto_mode == RNS.Identity.CRYPTO_HYBRID else 0
        request = self.REQUEST_HEADER.pack(self.SESSION_VERSION, mode_byte, session_id, nonce, logical_hash)
        request += ephemeral + ciphertext
        transcript = hashlib.sha256(request).digest()
        key = self._derive(b"".join(shared_parts), destination.hash, session_id, transcript)
        with self._lock:
            self._prune()
            if len(self.sessions) >= self.max_sessions:
                raise MemoryError("PQ session limit exceeded")
            self.sessions[(destination.hash, session_id)] = {
                "key": key, "transcript": transcript, "logical_hash": logical_hash,
                "logical_payload": logical_payload, "destination": destination,
                "updated": time.monotonic(), "established": False,
                "data_sent": False, "data_received": False, "seen": set(),
            }
        return session_id, request, fragment_record(RECORD_SESSION_REQUEST, request)

    def accept_request(self, identity, destination_hash, request):
        import RNS
        request = bytes(request)
        if len(request) < self.REQUEST_HEADER.size:
            raise ValueError("truncated PQ session request")
        version, mode_byte, session_id, nonce, logical_hash = self.REQUEST_HEADER.unpack_from(request)
        if version != self.SESSION_VERSION or mode_byte not in (0, 1):
            raise ValueError("unsupported PQ session request")
        offset = self.REQUEST_HEADER.size
        shared_parts = []
        if mode_byte:
            if identity.crypto_mode != RNS.Identity.CRYPTO_HYBRID or len(request) < offset + 32:
                raise ValueError("invalid hybrid PQ session request")
            from RNS.Cryptography import X25519PublicKey
            shared_parts.append(identity.prv.exchange(X25519PublicKey.from_public_bytes(request[offset:offset+32])))
            offset += 32
        if identity.pq_prv is None or len(request) != offset + RNS.Identity.PQ_KEM_CIPHERTEXT_SIZE:
            raise ValueError("invalid PQ session ciphertext")
        shared_parts.append(identity.pq_prv.decapsulate(request[offset:]))
        transcript = hashlib.sha256(request).digest()
        key = self._derive(b"".join(shared_parts), destination_hash, session_id, transcript)
        with self._lock:
            self._prune()
            if len(self.sessions) >= self.max_sessions:
                raise MemoryError("PQ session limit exceeded")
            self.sessions[(destination_hash, session_id)] = {
                "key": key, "transcript": transcript, "logical_hash": logical_hash,
                "updated": time.monotonic(), "established": True,
                "data_sent": False, "data_received": False, "seen": set(),
            }
        ack = self.ACK_HEADER.pack(self.SESSION_VERSION, session_id, transcript,
                                   hmac.new(key, b"ACK"+transcript, hashlib.sha256).digest())
        return ack, session_id

    def validate_ack(self, destination_hash, session_id, ack):
        if len(ack) != self.ACK_HEADER.size:
            return False
        version, ack_session, transcript, mac = self.ACK_HEADER.unpack(ack)
        if version != self.SESSION_VERSION or ack_session != session_id:
            return False
        with self._lock:
            state = self.sessions.get((destination_hash, session_id))
            if state is None or state["transcript"] != transcript:
                return False
            valid = hmac.compare_digest(
                mac, hmac.new(state["key"], b"ACK" + transcript, hashlib.sha256).digest())
            if valid:
                state["established"] = True
                state["updated"] = time.monotonic()
            return valid

    def data_fragments_after_ack(self, destination_hash, session_id):
        with self._lock:
            state = self.sessions.get((destination_hash, bytes(session_id)))
            if state is None or not state["established"] or state["data_sent"]:
                return []
            payload = state["logical_payload"]
        data = self.encrypt_data(destination_hash, session_id, payload)
        return fragment_record(RECORD_SESSION_DATA, data)

    def encrypt_data(self, destination_hash, session_id, plaintext):
        with self._lock:
            state = self.sessions.get((destination_hash, session_id))
            if state is None:
                raise KeyError("unknown PQ session")
            if not state["established"]:
                raise RuntimeError("PQ session has not been acknowledged")
            state["updated"] = time.monotonic()
            plaintext = bytes(plaintext)
            if not state["data_sent"] and hashlib.sha256(plaintext).digest() != state["logical_hash"]:
                raise ValueError("logical packet hash does not match PQ session request")
            state["data_sent"] = True
            body = hashlib.sha256(plaintext).digest() + plaintext
            return session_id + self._token(state["key"]).encrypt(body)

    def decrypt_data(self, destination_hash, data):
        if len(data) <= 8:
            return None
        session_id, ciphertext = data[:8], data[8:]
        with self._lock:
            state = self.sessions.get((destination_hash, session_id))
            if state is None or not state["established"]:
                return None
            digest = hashlib.sha256(ciphertext).digest()
            if digest in state["seen"]:
                return None
            try:
                body = self._token(state["key"]).decrypt(ciphertext)
            except (TypeError, ValueError):
                return None
            if body is None or len(body) < 32:
                return None
            plaintext, plain_digest = body[32:], body[:32]
            if hashlib.sha256(plaintext).digest() != plain_digest:
                return None
            if not state["data_received"] and plain_digest != state["logical_hash"]:
                return None
            state["seen"].add(digest)
            if len(state["seen"]) > 128:
                state["seen"].pop()
            state["data_received"] = True
            state["updated"] = time.monotonic()
            return plaintext
