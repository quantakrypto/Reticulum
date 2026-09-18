#!/usr/bin/env python3
"""Discover and exercise PQ Reticulum destinations.

Run one instance on each Reticulum node. Both instances announce the same
application destination, identify peers through /info, and then exercise
single-destination packets, link packets, and resources.
"""

import argparse
import os
import sys
import threading
import time

import RNS
from RNS.vendor import umsgpack


APP_NAME = "pq_flow"
INFO_ASPECT = "info"
INFO_PATH = "/info"
PROTOCOL_VERSION = 1
TEST_INTERVAL = 30.0
PACKET_RECEIPT_TIMEOUT = 30.0
RESOURCE_TIMEOUT = 120.0
ANNOUNCE_INTERVAL = 10.0
ANNOUNCE_APP_DATA = b"RNS-PQ-FLOW\x01"
DIRECT_PACKET_DATA = b"RNS-PQ-FLOW-DIRECT-PACKET\x00"
LINK_PACKET_DATA = b"RNS-PQ-FLOW-LINK-PACKET\x00"
RESOURCE_DATA = b"RNS-PQ-FLOW-RESOURCE\x00"
RESOURCE_SIZE = 64 * 1024


class AnnounceHandler:
    """Log every announce and identify PQ flow servers."""

    aspect_filter = None

    def __init__(self, server):
        self.server = server

    def received_announce(self, destination_hash, announced_identity, app_data):
        self.server.received_announce(
            destination_hash, announced_identity, app_data
        )


class PQFlowServer:
    def __init__(self, config_path=None, identity_path=None):
        if not RNS.Cryptography.pq_available():
            raise RuntimeError(
                "PQ support is unavailable; install liboqs-python and its ML-KEM/ML-DSA backend"
            )

        RNS.Identity.set_crypto_mode(RNS.Identity.CRYPTO_PQ)
        self.reticulum = RNS.Reticulum(config_path)
        # Reticulum configuration may select legacy mode by default. The
        # application identity used by this probe must remain explicitly PQ.
        RNS.Identity.set_crypto_mode(RNS.Identity.CRYPTO_PQ)
        self.identity = self._load_identity(identity_path)
        if self.identity.crypto_mode != RNS.Identity.CRYPTO_PQ:
            raise RuntimeError("The test server identity is not a PQ identity")

        self.destination = RNS.Destination(
            self.identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APP_NAME,
            INFO_ASPECT,
        )
        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self.destination.set_default_app_data(ANNOUNCE_APP_DATA)
        self.destination.set_link_established_callback(self.incoming_link_established)
        self.destination.set_packet_callback(self.incoming_destination_packet)
        self.destination.register_request_handler(
            INFO_PATH,
            response_generator=self.info_response,
            allow=RNS.Destination.ALLOW_ALL,
        )

        self.announce_handler = AnnounceHandler(self)
        RNS.Transport.register_announce_handler(self.announce_handler)
        self.stop_event = threading.Event()
        self.peers = {}
        self.peers_lock = threading.Lock()
        self.seen_announces = set()
        self.sent_first = False

    @staticmethod
    def _load_identity(identity_path):
        if identity_path and os.path.exists(identity_path):
            identity = RNS.Identity.from_file(identity_path)
            if identity is None:
                raise RuntimeError("Could not load identity from "+identity_path)
            return identity

        identity = RNS.Identity()
        if identity_path:
            parent = os.path.dirname(os.path.abspath(identity_path))
            os.makedirs(parent, exist_ok=True)
            if not identity.to_file(identity_path):
                raise RuntimeError("Could not save identity to "+identity_path)
        return identity

    @staticmethod
    def _hash_text(identity_hash):
        return RNS.prettyhexrep(identity_hash)

    @staticmethod
    def _app_data_text(app_data):
        if app_data is None:
            return "<none>"
        if app_data == ANNOUNCE_APP_DATA:
            return "RNS-PQ-FLOW marker"
        return RNS.hexrep(app_data)

    @staticmethod
    def _result(side, capability, passed, detail=""):
        status = "PASS" if passed else "FAIL"
        suffix = " ("+detail+")" if detail else ""
        RNS.log("[PQ-FLOW] "+side+" "+capability+" "+status+suffix)

    def start(self):
        RNS.log(
            "[PQ-FLOW] started with PQ identity "+self._hash_text(self.identity.hash)
        )
        RNS.log(
            "[PQ-FLOW] info destination "+self._hash_text(self.destination.hash)
        )
        threading.Thread(target=self.announce_loop, daemon=True).start()
        threading.Thread(target=self.test_loop, daemon=True).start()

    def run(self):
        self.start()
        try:
            while not self.stop_event.wait(1.0):
                pass
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        if self.stop_event.is_set():
            return
        self.stop_event.set()
        RNS.Transport.deregister_announce_handler(self.announce_handler)
        RNS.log("[PQ-FLOW] stopped")

    def announce_loop(self):
        while not self.stop_event.is_set():
            try:
                self.destination.announce(app_data=ANNOUNCE_APP_DATA)
                if not self.sent_first:
                    RNS.log(
                        "[PQ-FLOW] SENT ANNOUNCE destination="+
                        self._hash_text(self.destination.hash)
                    )
                    self.sent_first = True
            except Exception as exc:
                RNS.log("[PQ-FLOW] SEND ANNOUNCE FAIL: "+str(exc), RNS.LOG_ERROR)
            self.stop_event.wait(ANNOUNCE_INTERVAL)

    def received_announce(self, destination_hash, announced_identity, app_data):
        if announced_identity and announced_identity.hash == self.identity.hash:
            return

        with self.peers_lock:
            is_new_destination = destination_hash not in self.seen_announces
            if is_new_destination:
                self.seen_announces.add(destination_hash)

            if app_data != ANNOUNCE_APP_DATA or announced_identity is None:
                peer = None
                peer_is_new = False
            else:
                peer_key = announced_identity.hash
                peer = self.peers.get(peer_key)
                peer_is_new = peer is None
                if peer is None:
                    peer = {
                        "key": peer_key,
                        "identity": announced_identity,
                        "destination_hash": destination_hash,
                        "testing": False,
                        "link": None,
                        "direct_packet": None,
                        "link_packet": None,
                        "resource": None,
                    }
                    self.peers[peer_key] = peer
                else:
                    peer["identity"] = announced_identity
                    peer["destination_hash"] = destination_hash

        if is_new_destination:
            announced_identity_text = (
                self._hash_text(announced_identity.hash)
                if announced_identity else "<unknown>"
            )
            RNS.log(
                "[PQ-FLOW] RECEIVED ANNOUNCE destination="+
                self._hash_text(destination_hash)+
                " identity="+announced_identity_text
            )
            RNS.log("[PQ-FLOW] announce app_data="+self._app_data_text(app_data))
        if peer_is_new:
            RNS.log(
                "[PQ-FLOW] identified server "+self._hash_text(peer["key"])+
                "; testing on the 30s schedule"
            )

    def test_loop(self):
        while not self.stop_event.wait(TEST_INTERVAL):
            self.run_test_cycle()

    def run_test_cycle(self):
        jobs = []
        with self.peers_lock:
            for peer_key, peer in self.peers.items():
                if peer["testing"]:
                    continue
                peer["testing"] = True
                peer["direct_packet"] = None
                peer["link_packet"] = None
                peer["resource"] = None
                jobs.append((peer_key, peer))

        RNS.log("[PQ-FLOW] starting scheduled test cycle")
        for peer_key, peer in jobs:
            threading.Thread(
                target=self.test_peer, args=(peer_key, peer), daemon=True
            ).start()
    def info_response(
        self, path, data, request_id, link_id, remote_identity, requested_at
    ):
        remote = self._hash_text(remote_identity.hash) if remote_identity else "<unknown>"
        RNS.log("[PQ-FLOW] RECEIVER Info request from "+remote)
        return umsgpack.packb({
            "kind": "rns-pq-flow",
            "protocol": PROTOCOL_VERSION,
            "crypto": RNS.Identity.CRYPTO_PQ,
            "identity_hash": self.identity.hash,
            "destination_hash": self.destination.hash,
            "capabilities": ["link", "packet", "resource"],
        })

    def _configure_link(self, link, closed_callback):
        link.set_link_closed_callback(closed_callback)
        link.set_packet_callback(self.incoming_link_packet)
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_started_callback(self.incoming_resource_started)
        link.set_resource_concluded_callback(self.incoming_resource_concluded)

    def incoming_link_established(self, link):
        self._configure_link(link, self.link_closed)
        self._result("RECEIVER", "Link", True, "link="+str(link))

    def incoming_destination_packet(self, data, packet):
        passed = data.startswith(DIRECT_PACKET_DATA)
        self._result(
            "RECEIVER", "Packet", passed,
            "direct destination packet size="+str(len(data)),
        )

    def incoming_link_packet(self, data, packet):
        passed = data.startswith(LINK_PACKET_DATA)
        self._result(
            "RECEIVER", "Link Packet", passed,
            "link packet size="+str(len(data)),
        )

    def incoming_resource_started(self, resource):
        resource.progress_callback(self.incoming_resource_progress)
        RNS.log(
            "[PQ-FLOW] RECEIVER Resource accepted size="+
            str(resource.size)+" parts="+str(resource.total_parts)+
            " sdu="+str(resource.sdu)
        )

    def incoming_resource_progress(self, resource):
        RNS.log(
            "[PQ-FLOW] RECEIVER Resource progress "+
            str(resource.received_count)+"/"+str(resource.total_parts),
            RNS.LOG_DEBUG,
        )

    def incoming_resource_concluded(self, resource):
        payload = b""
        passed = False
        if resource.status == RNS.Resource.COMPLETE:
            try:
                resource.data.seek(0)
                payload = resource.data.read()
                passed = (
                    len(payload) == RESOURCE_SIZE and
                    payload.startswith(RESOURCE_DATA)
                )
            except Exception as exc:
                RNS.log("[PQ-FLOW] RECEIVER Resource read failed: "+str(exc), RNS.LOG_ERROR)
        self._result(
            "RECEIVER", "Resource", passed,
            "status="+str(resource.status)+
            " size="+str(len(payload))+
            " parts="+str(getattr(resource, "received_count", "?"))+
            "/"+str(getattr(resource, "total_parts", "?"))+
            " retries="+str(getattr(resource, "retries_left", "?"))
        )

    def test_peer(self, peer_key, peer):
        try:
            peer_destination = RNS.Destination(
                peer["identity"],
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                APP_NAME,
                INFO_ASPECT,
            )
            peer["destination"] = peer_destination
            link = RNS.Link(
                peer_destination,
                established_callback=lambda active_link: self.outgoing_link_established(
                    peer_key, peer, active_link
                ),
                closed_callback=lambda closed_link: self.outgoing_link_closed(
                    peer_key, peer, closed_link
                ),
            )
            peer["link"] = link
            RNS.log(
                "[PQ-FLOW] testing peer "+self._hash_text(peer_key)+
                " via link "+str(link)
            )
        except Exception as exc:
            self._result("SENDER", "Link", False, str(exc))
            self._peer_failed(peer_key, peer)

    def outgoing_link_established(self, peer_key, peer, link):
        self._configure_link(link, lambda closed_link: self.outgoing_link_closed(
            peer_key, peer, closed_link
        ))
        self._result("SENDER", "Link", True, "link="+str(link))
        try:
            receipt = link.request(
                INFO_PATH,
                response_callback=lambda response: self.info_received(
                    peer_key, peer, response
                ),
                failed_callback=lambda failed: self.info_failed(
                    peer_key, peer, failed
                ),
            )
            if receipt is False:
                self.info_failed(peer_key, peer, None)
            else:
                RNS.log("[PQ-FLOW] SENDER Info request sent to "+self._hash_text(peer_key))
        except Exception as exc:
            self.info_failed(peer_key, peer, exc)

    def info_received(self, peer_key, peer, receipt):
        try:
            info = umsgpack.unpackb(receipt.response)
            valid = (
                isinstance(info, dict) and
                info.get("kind") == "rns-pq-flow" and
                info.get("protocol") == PROTOCOL_VERSION and
                info.get("crypto") == RNS.Identity.CRYPTO_PQ and
                info.get("identity_hash") == peer_key and
                set(info.get("capabilities", [])) >= {"link", "packet", "resource"}
            )
            self._result("SENDER", "Info", valid, "peer="+self._hash_text(peer_key))
            if not valid:
                self._peer_failed(peer_key, peer)
                return
            self.send_tests(peer_key, peer)
        except Exception as exc:
            self._result("SENDER", "Info", False, str(exc))
            self._peer_failed(peer_key, peer)

    def info_failed(self, peer_key, peer, receipt):
        detail = "request failed"
        if receipt is not None and hasattr(receipt, "status"):
            detail += " status="+str(receipt.status)
        self._result("SENDER", "Info", False, detail)
        self._peer_failed(peer_key, peer)

    def send_tests(self, peer_key, peer):
        peer_destination = peer["destination"]
        link = peer["link"]

        try:
            packet = RNS.Packet(
                peer_destination, DIRECT_PACKET_DATA+self.identity.hash
            )
            receipt = packet.send()
            if receipt is False:
                self._result("SENDER", "Packet", False, "direct packet rejected")
                peer["direct_packet"] = False
                self._maybe_finish_test(peer)
            else:
                peer["direct_packet"] = None
                receipt.set_timeout(PACKET_RECEIPT_TIMEOUT)
                receipt.set_delivery_callback(
                    lambda delivered: self._sender_packet_result(
                        peer, "Packet", "direct_packet", delivered
                    )
                )
                receipt.set_timeout_callback(
                    lambda timed_out: self._sender_packet_result(
                        peer, "Packet", "direct_packet", None
                    )
                )
                RNS.log("[PQ-FLOW] SENDER direct Packet sent to "+self._hash_text(peer_key))
        except Exception as exc:
            peer["direct_packet"] = False
            self._result("SENDER", "Packet", False, str(exc))
            self._maybe_finish_test(peer)

        try:
            packet = RNS.Packet(link, LINK_PACKET_DATA+self.identity.hash)
            receipt = packet.send()
            if receipt is False:
                self._result("SENDER", "Link Packet", False, "packet rejected")
                peer["link_packet"] = False
                self._maybe_finish_test(peer)
            else:
                peer["link_packet"] = None
                receipt.set_timeout(PACKET_RECEIPT_TIMEOUT)
                receipt.set_delivery_callback(
                    lambda delivered: self._sender_packet_result(
                        peer, "Link Packet", "link_packet", delivered
                    )
                )
                receipt.set_timeout_callback(
                    lambda timed_out: self._sender_packet_result(
                        peer, "Link Packet", "link_packet", None
                    )
                )
                RNS.log("[PQ-FLOW] SENDER link Packet sent to "+self._hash_text(peer_key))
        except Exception as exc:
            peer["link_packet"] = False
            self._result("SENDER", "Link Packet", False, str(exc))
            self._maybe_finish_test(peer)

        try:
            resource_payload = RESOURCE_DATA+self.identity.hash
            resource_payload += b"\x00" * (RESOURCE_SIZE-len(resource_payload))
            resource = RNS.Resource(
                resource_payload,
                link,
                metadata={"kind": "rns-pq-flow", "protocol": PROTOCOL_VERSION},
                auto_compress=False,
                timeout=RESOURCE_TIMEOUT,
                callback=lambda item: self.sender_resource_concluded(peer, item),
            )
            RNS.log(
                "[PQ-FLOW] SENDER Resource started size="+
                str(len(resource_payload))+
                " parts="+str(resource.total_parts)+
                " sdu="+str(resource.sdu)+
                " timeout="+str(resource.timeout)+
                " for "+self._hash_text(peer_key)
            )
        except Exception as exc:
            peer["resource"] = False
            self._result("SENDER", "Resource", False, str(exc))
            self._maybe_finish_test(peer)

    def _maybe_finish_test(self, peer):
        with self.peers_lock:
            if not peer["testing"]:
                return
            if any(peer[key] is None for key in (
                    "direct_packet", "link_packet", "resource")):
                return
            peer["testing"] = False
            link = peer.get("link")

        RNS.log(
            "[PQ-FLOW] scheduled test complete for "+
            self._hash_text(peer["key"])
        )
        if link is not None:
            try:
                link.teardown()
            except Exception:
                pass

    def _sender_packet_result(self, peer, capability, state_key, receipt):
        passed = receipt is not None and receipt.status == RNS.PacketReceipt.DELIVERED
        peer[state_key] = passed
        detail = "delivery proof" if passed else "delivery timeout or failure"
        self._result("SENDER", capability, passed, detail)
        self._maybe_finish_test(peer)

    def sender_resource_concluded(self, peer, resource):
        passed = resource.status == RNS.Resource.COMPLETE
        self._result(
            "SENDER", "Resource", passed,
            "status="+str(resource.status)+
            " parts="+str(getattr(resource, "sent_parts", "?"))+
            "/"+str(getattr(resource, "total_parts", "?"))+
            " retries="+str(getattr(resource, "retries_left", "?"))
        )
        peer["resource"] = passed
        self._maybe_finish_test(peer)

    def link_closed(self, link):
        RNS.log("[PQ-FLOW] RECEIVER Link closed "+str(link))

    def outgoing_link_closed(self, peer_key, peer, link):
        RNS.log("[PQ-FLOW] SENDER Link closed "+self._hash_text(peer_key))
        self._peer_failed(peer_key, peer)

    def _peer_failed(self, peer_key, peer):
        link = peer.get("link")
        if link is not None:
            try:
                link.teardown()
            except Exception:
                pass
        with self.peers_lock:
            current = self.peers.get(peer_key)
            if current is peer:
                peer["testing"] = False


def main():
    parser = argparse.ArgumentParser(
        description="Discover and test Reticulum PQ flows on every announced peer"
    )
    parser.add_argument(
        "--config", default=None,
        help="path to an alternative Reticulum config directory",
    )
    parser.add_argument(
        "--identity", default=None,
        help="path for a persistent PQ identity; otherwise generate one",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="enable Reticulum debug logging",
    )
    args = parser.parse_args()
    RNS.loglevel = RNS.LOG_DEBUG if args.verbose else RNS.LOG_INFO

    try:
        PQFlowServer(args.config, args.identity).run()
    except KeyboardInterrupt:
        print("")
    except Exception as exc:
        RNS.log("[PQ-FLOW] fatal: "+str(exc), RNS.LOG_ERROR)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
