#!/usr/bin/env python3
"""Interactive point-to-point chat over a PQ Reticulum link."""

import argparse
import os
import sys
import threading
import time

import RNS
from RNS.vendor import umsgpack


APP_NAME = "pqc_chat"
CHAT_ASPECT = "chat"
PROTOCOL_VERSION = 1
ANNOUNCE_INTERVAL = 10.0
PATH_TIMEOUT = 60.0


class PQCChat:
    def __init__(self, config_path=None, identity_path=None):
        if not RNS.Cryptography.pq_available():
            raise RuntimeError(
                "PQ support is unavailable; install liboqs-python with ML-KEM-768 and ML-DSA-65"
            )

        RNS.Identity.set_crypto_mode(RNS.Identity.CRYPTO_PQ)
        self.reticulum = RNS.Reticulum(config_path)
        RNS.Identity.set_crypto_mode(RNS.Identity.CRYPTO_PQ)
        self.identity = self._load_identity(identity_path)
        if self.identity is None:
            raise RuntimeError("Could not load the supplied identity")
        if self.identity.crypto_mode != RNS.Identity.CRYPTO_PQ:
            raise RuntimeError("The supplied identity is not a PQ identity")

        self.destination = RNS.Destination(
            self.identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APP_NAME,
            CHAT_ASPECT,
        )
        self.destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
        self.destination.set_default_app_data(b"RNS-PQC-CHAT\x01")
        self.destination.set_link_established_callback(self._incoming_link_established)

        self.state_lock = threading.Lock()
        self.active_link = None
        self.active_peer = None
        self.outgoing_link = None
        self.pending_requests = []
        self.stop_event = threading.Event()

    @staticmethod
    def _load_identity(identity_path):
        if identity_path and os.path.exists(identity_path):
            return RNS.Identity.from_file(identity_path)

        identity = RNS.Identity()
        if identity_path:
            parent = os.path.dirname(os.path.abspath(identity_path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            if not identity.to_file(identity_path):
                raise RuntimeError("Could not save identity to "+identity_path)
        return identity

    @staticmethod
    def _display_hash(value):
        return RNS.prettyhexrep(value)

    @staticmethod
    def _message(kind, **fields):
        return umsgpack.packb({"protocol": PROTOCOL_VERSION, "type": kind, **fields})

    @staticmethod
    def _unpack(data):
        try:
            message = umsgpack.unpackb(data)
            if not isinstance(message, dict):
                return None
            if message.get("protocol") != PROTOCOL_VERSION:
                return None
            return message
        except Exception:
            return None

    def start(self):
        print("Your PQ chat destination: "+self._display_hash(self.destination.hash))
        print("Announcing destination every "+str(int(ANNOUNCE_INTERVAL))+" seconds")
        threading.Thread(target=self._announce_loop, daemon=True).start()

    def stop(self):
        if self.stop_event.is_set():
            return
        self.stop_event.set()
        with self.state_lock:
            links = [self.active_link, self.outgoing_link]
            links.extend(request["link"] for request in self.pending_requests)
            self.active_link = None
            self.outgoing_link = None
            self.pending_requests = []
        for link in links:
            if link is not None:
                try:
                    link.teardown()
                except Exception:
                    pass

    def _announce_loop(self):
        while not self.stop_event.is_set():
            try:
                self.destination.announce()
            except Exception as exc:
                RNS.log("Could not announce PQ chat destination: "+str(exc), RNS.LOG_ERROR)
            self.stop_event.wait(ANNOUNCE_INTERVAL)

    def connect(self, destination_text):
        destination_hash = self._parse_destination(destination_text)
        if destination_hash is None:
            raise ValueError("Invalid destination; expected a hexadecimal destination hash")

        if not RNS.Transport.has_path(destination_hash):
            RNS.log("Requesting path to "+self._display_hash(destination_hash))
            RNS.Transport.request_path(destination_hash)
            deadline = time.time() + PATH_TIMEOUT
            while not RNS.Transport.has_path(destination_hash):
                if time.time() >= deadline:
                    raise TimeoutError("Timed out waiting for a path to the destination")
                time.sleep(0.1)

        deadline = time.time() + PATH_TIMEOUT
        remote_identity = RNS.Identity.recall(destination_hash)
        while remote_identity is None and time.time() < deadline:
            time.sleep(0.1)
            remote_identity = RNS.Identity.recall(destination_hash)
        if remote_identity is None:
            raise RuntimeError("Could not recall the identity for the destination")
        if remote_identity.crypto_mode != RNS.Identity.CRYPTO_PQ:
            raise RuntimeError("The destination is not a PQ destination")

        remote_destination = RNS.Destination(
            remote_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            APP_NAME,
            CHAT_ASPECT,
        )
        print("Establishing PQ link with "+self._display_hash(destination_hash)+"...")
        link = RNS.Link(
            remote_destination,
            established_callback=self._outgoing_link_established,
            closed_callback=self._link_closed,
        )
        link.set_packet_callback(self._packet_received)
        with self.state_lock:
            self.outgoing_link = link

    @staticmethod
    def _parse_destination(destination_text):
        try:
            expected_length = (RNS.Reticulum.TRUNCATED_HASHLENGTH // 8) * 2
            value = destination_text.strip()
            if len(value) != expected_length:
                return None
            return bytes.fromhex(value)
        except (TypeError, ValueError):
            return None

    def _configure_link(self, link):
        link.set_packet_callback(self._packet_received)
        link.set_link_closed_callback(self._link_closed)

    def _incoming_link_established(self, link):
        self._configure_link(link)
        peer = link.get_remote_identity()
        peer_text = str(peer) if peer is not None else "unknown peer"
        RNS.log("Incoming PQ link established from "+peer_text)

    def _outgoing_link_established(self, link):
        self._configure_link(link)
        with self.state_lock:
            if self.active_link is not None:
                busy = True
            else:
                busy = False
                if self.outgoing_link is None:
                    self.outgoing_link = link
        if busy:
            self._send(link, self._message("chat_reject"))
            link.teardown()
            return
        RNS.log("PQ link established; requesting chat")
        if not self._send(link, self._message("chat_request")):
            self._link_closed(link)

    def _packet_received(self, data, packet):
        message = self._unpack(data)
        if message is None:
            RNS.log("Ignoring malformed PQ chat packet", RNS.LOG_WARNING)
            return

        link = packet.link
        kind = message.get("type")
        if kind == "chat_request":
            self._received_chat_request(link)
        elif kind == "chat_accept":
            self._received_chat_accept(link)
        elif kind == "chat_reject":
            self._received_chat_reject(link)
        elif kind == "chat_message":
            self._received_chat_message(link, message.get("text"))
        else:
            RNS.log("Ignoring unknown PQ chat message type: "+str(kind), RNS.LOG_WARNING)

    def _received_chat_request(self, link):
        with self.state_lock:
            busy = self.active_link is not None or (
                self.outgoing_link is not None and self.outgoing_link is not link
            )
            known = any(request["link"] is link for request in self.pending_requests)
            if not busy and not known:
                self.pending_requests.append({"link": link})

        if busy:
            self._send(link, self._message("chat_reject"))
            link.teardown()
            return
        print("\nIncoming PQ chat request. Accept? [y/N] ", end="", flush=True)

    def _received_chat_accept(self, link):
        with self.state_lock:
            if self.outgoing_link is not link:
                return
            self.outgoing_link = None
            self.active_link = link
            self.active_peer = link.get_remote_identity()
        print("\nChat request accepted. You can now send messages.")
        print("> ", end="", flush=True)

    def _received_chat_reject(self, link):
        with self.state_lock:
            if self.outgoing_link is link:
                self.outgoing_link = None
        print("\nChat request rejected by the destination.")
        link.teardown()

    def _received_chat_message(self, link, text):
        if not isinstance(text, str):
            return
        with self.state_lock:
            if self.active_link is not link:
                return
        print("\nPeer: "+text)
        print("> ", end="", flush=True)

    def _send(self, link, data):
        if len(data) > RNS.Link.MDU:
            RNS.log("Message exceeds the link packet MDU", RNS.LOG_ERROR)
            return False
        try:
            return RNS.Packet(link, data).send() is not False
        except Exception as exc:
            RNS.log("Could not send PQ chat packet: "+str(exc), RNS.LOG_ERROR)
            return False

    def _link_closed(self, link):
        with self.state_lock:
            self.pending_requests = [
                request for request in self.pending_requests if request["link"] is not link
            ]
            was_active = self.active_link is link
            if self.outgoing_link is link:
                self.outgoing_link = None
            if was_active:
                self.active_link = None
                self.active_peer = None
        if was_active:
            print("\nChat link closed.")

    def _accept_pending(self):
        with self.state_lock:
            if not self.pending_requests:
                return False
            request = self.pending_requests.pop(0)
            self.active_link = request["link"]
            self.active_peer = request["link"].get_remote_identity()
        if self._send(request["link"], self._message("chat_accept")):
            print("Chat request accepted. You can now send messages.")
            return True
        self._link_closed(request["link"])
        return False

    def _reject_pending(self):
        with self.state_lock:
            if not self.pending_requests:
                return False
            request = self.pending_requests.pop(0)
        self._send(request["link"], self._message("chat_reject"))
        request["link"].teardown()
        print("Chat request rejected.")
        return True

    def _send_chat_message(self, text):
        with self.state_lock:
            link = self.active_link
        if link is None:
            print("No accepted chat link.")
            return
        if not self._send(link, self._message("chat_message", text=text)):
            print("Message could not be sent.")

    def console_loop(self):
        print("Enter a destination hash to request chat, or press Enter to wait.")
        while not self.stop_event.is_set():
            try:
                line = input("> ")
            except EOFError:
                return
            except KeyboardInterrupt:
                return

            with self.state_lock:
                has_pending = bool(self.pending_requests)
                has_active = self.active_link is not None
                has_outgoing = self.outgoing_link is not None

            if has_pending:
                if line.strip().lower() in ("y", "yes"):
                    self._accept_pending()
                else:
                    self._reject_pending()
                continue

            if line.strip().lower() in ("quit", "exit", "q"):
                return
            if not line:
                continue
            if has_active:
                self._send_chat_message(line)
            elif has_outgoing:
                print("Waiting for the chat request to be accepted.")
            else:
                try:
                    self.connect(line)
                except Exception as exc:
                    print("Could not connect: "+str(exc))

    def run(self, destination_text=None):
        self.start()
        if destination_text is None:
            destination_text = input("Destination to chat with (or press Enter to wait): ").strip()
        if destination_text:
            self.connect(destination_text)
        try:
            self.console_loop()
        finally:
            self.stop()


def main():
    parser = argparse.ArgumentParser(description="Interactive PQ Reticulum chat")
    parser.add_argument(
        "-i", "--identity", default=None,
        help="path to a PQ identity file; create it if it does not exist",
    )
    parser.add_argument(
        "-d", "--destination", default=None,
        help="destination hash to request a chat with",
    )
    parser.add_argument(
        "--config", default=None,
        help="path to an alternative Reticulum config directory",
    )
    args = parser.parse_args()

    try:
        PQCChat(args.config, args.identity).run(args.destination)
    except KeyboardInterrupt:
        print("")
    except Exception as exc:
        RNS.log("Fatal: "+str(exc), RNS.LOG_ERROR)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
