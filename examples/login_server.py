#!/usr/bin/env python3
"""
Simple login server example: Accept and authenticate client logins.

This example demonstrates how to set up a basic authentication server
that responds to login requests from mesh clients, validates credentials,
and manages an access control list (ACL).

The server supports:
- Admin password authentication
- Guest password authentication
- ACL-based authentication (blank password)
- Automatic response to login attempts

This example implements the application-level authentication logic
(password validation, ACL management, permission assignment).
The handler (LoginServerHandler) performs only protocol operations.
"""

import asyncio
import time
from typing import Dict, Optional

from common import RADIO_TYPES, create_mesh_node

from openhop_core.node.handlers.login_server import LoginServerHandler
from openhop_core.protocol import Identity, LocalIdentity
from openhop_core.protocol.constants import (
    PERM_ACL_ADMIN,
    PERM_ACL_GUEST,
    PERM_ACL_ROLE_MASK,
    PUB_KEY_SIZE,
    acl_is_admin,
    acl_role,
)


def create_mesh_node_with_identity(
    node_name: str, radio_type: str, serial_port: str, identity: LocalIdentity
) -> tuple[any, LocalIdentity]:
    """Create a mesh node with a specific identity (modified from common.py)"""
    import logging
    import os
    import sys

    # Set up logging (copied from common.py)
    logger = logging.getLogger(__name__)

    # Add the src directory to the path so we can import openhop_core
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

    from common import create_radio

    from openhop_core.node.node import MeshNode

    logger.info(f"Creating mesh node with name: {node_name} using {radio_type} radio")

    try:
        # Use the provided identity instead of creating a new one
        logger.info(
            f"Using provided identity with public key: {identity.get_public_key().hex()[:16]}..."
        )

        # Create the radio (copied from common.py logic)
        radio = create_radio(radio_type, serial_port)

        # Initialize radio based on type
        if radio_type == "kiss-tnc":
            import time

            time.sleep(1)  # Give KISS time to initialize
            if hasattr(radio, "begin"):
                radio.begin()
            # Check KISS status
            if hasattr(radio, "kiss_mode_active") and radio.kiss_mode_active:
                logger.info("KISS mode is active")
            else:
                logger.warning("KISS mode may not be active")
                print("Warning: KISS mode may not be active")
        else:
            logger.debug("Calling radio.begin()...")
            radio.begin()
            logger.info("Radio initialized successfully")

        # Create a mesh node with the radio and identity
        config = {"node": {"name": node_name}}
        logger.debug(f"Creating MeshNode with config: {config}")
        mesh_node = MeshNode(radio=radio, local_identity=identity, config=config)
        logger.info(f"MeshNode created successfully: {node_name}")

        return mesh_node, identity

    except Exception as e:
        logger.error(f"Failed to create mesh node: {e}")
        raise


# =============================================================================
# HARDCODED EXAMPLE CREDENTIALS - FOR TESTING ONLY!
# =============================================================================
# Server identity (hardcoded for easy testing)
# Use a deterministic seed to always generate the same identity
EXAMPLE_SEED = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")

# Example credentials
EXAMPLE_ADMIN_PASSWORD = "admin123"
EXAMPLE_GUEST_PASSWORD = "guest123"
# =============================================================================

# Permission levels come from openhop_core.protocol.constants, which mirrors
# firmware ClientACL.h: the role is the low two bits of the permissions byte
# (GUEST=0, READ_ONLY=1, READ_WRITE=2, ADMIN=3). Do not redefine them here —
# a local copy on different numbering is exactly what made OpenHop admins
# decode as read-write in stock MeshCore clients.


class ClientInfo:
    """Represents an authenticated client in the access control list."""

    def __init__(self, identity: Identity, permissions: int = 0):
        self.id = identity
        self.permissions = permissions
        self.shared_secret = b""
        self.last_timestamp = 0
        self.last_activity = 0
        self.last_login_success = 0
        self.out_path_len = -1  # -1 means no path, need to discover
        self.out_path = bytearray()

    def is_admin(self) -> bool:
        """Check if client has admin permissions."""
        return acl_is_admin(self.permissions)

    def is_guest(self) -> bool:
        """Check if client has guest permissions."""
        return acl_role(self.permissions) == PERM_ACL_GUEST


class ClientACL:
    """
    Access Control List for managing authenticated clients.

    Implements application-level authentication logic:
    - Password validation
    - Client state management
    - Permission assignment
    - Replay attack detection
    """

    def __init__(
        self,
        max_clients: int = 32,
        admin_password: str = "admin123",
        guest_password: str = "guest123",
    ):
        self.max_clients = max_clients
        self.admin_password = admin_password
        self.guest_password = guest_password
        self.clients: Dict[bytes, ClientInfo] = {}  # pub_key -> ClientInfo

    def authenticate_client(
        self, client_identity: Identity, shared_secret: bytes, password: str, timestamp: int
    ) -> tuple[bool, int]:
        """
        Authenticate a client login request.

        This is the authentication callback used by LoginServerHandler.
        It implements the application's password validation and ACL logic.

        Args:
            client_identity: Client's identity
            shared_secret: ECDH shared secret for encryption
            password: Password provided by client
            timestamp: Timestamp from client request

        Returns:
            (success: bool, permissions: int) - True/permissions on success, False/0 on failure
        """
        pub_key = client_identity.get_public_key()[:PUB_KEY_SIZE]

        # Check for blank password (ACL-only authentication)
        if not password:
            client = self.clients.get(pub_key)
            if client is None:
                print(f"[ACL] Blank password, sender not in ACL")
                return False, 0
            # Client exists in ACL, allow login with existing permissions
            print(f"[ACL] ACL-based login for {pub_key[:6].hex()}...")
            return True, client.permissions

        # Validate password
        permissions = 0
        if password == self.admin_password:
            permissions = PERM_ACL_ADMIN
            print(f"[ACL] Admin password validated")
        elif self.guest_password and password == self.guest_password:
            permissions = PERM_ACL_GUEST
            print(f"[ACL] Guest password validated")
        else:
            print(f"[ACL] Invalid password")
            return False, 0

        # Get or create client
        client = self.clients.get(pub_key)
        if client is None:
            # Check capacity
            if len(self.clients) >= self.max_clients:
                print(f"[ACL] ACL full, cannot add client")
                return False, 0

            # Add new client
            client = ClientInfo(client_identity, 0)
            self.clients[pub_key] = client
            print(f"[ACL] Added new client {pub_key[:6].hex()}...")

        # Check for replay attack
        if timestamp <= client.last_timestamp:
            print(
                f"[ACL] Possible replay attack! timestamp={timestamp}, last={client.last_timestamp}"
            )
            return False, 0

        # Update client state
        client.last_timestamp = timestamp
        client.last_activity = int(time.time())
        client.last_login_success = int(time.time())
        client.permissions &= ~PERM_ACL_ROLE_MASK
        client.permissions |= permissions
        client.shared_secret = shared_secret

        print(f"[ACL] Login success! Permissions: {'ADMIN' if client.is_admin() else 'GUEST'}")
        return True, client.permissions

    def get_client(self, pub_key: bytes) -> Optional[ClientInfo]:
        """Get client by public key."""
        return self.clients.get(pub_key[:PUB_KEY_SIZE])

    def get_num_clients(self) -> int:
        """Get number of clients in ACL."""
        return len(self.clients)

    def get_all_clients(self):
        """Get all clients."""
        return list(self.clients.values())

    def remove_client(self, pub_key: bytes) -> bool:
        """Remove client from ACL."""
        key = pub_key[:PUB_KEY_SIZE]
        if key in self.clients:
            del self.clients[key]
            return True
        return False


async def run_login_server(
    radio_type: str = "waveshare",
    serial_port: str = "/dev/ttyUSB0",
    admin_password: str = EXAMPLE_ADMIN_PASSWORD,
    guest_password: str = EXAMPLE_GUEST_PASSWORD,
    use_hardcoded_identity: bool = True,
):
    """
    Run a login authentication server.

    Args:
        radio_type: Radio hardware type ("waveshare", "uconsole", etc.)
        serial_port: Serial port for KISS TNC
        admin_password: Password for admin access
        guest_password: Password for guest access (empty string to disable)
        use_hardcoded_identity: Use hardcoded identity for easy testing
    """
    print("=" * 60)
    print("openHop Core - Login Server Example")
    print("=" * 60)
    print(f"Admin Password: {admin_password}")
    print(f"Guest Password: {guest_password if guest_password else '<disabled>'}")
    print(f"Hardcoded Identity: {use_hardcoded_identity}")
    print("=" * 60)

    # Create mesh node with optional hardcoded identity
    if use_hardcoded_identity:
        print("Using hardcoded example identity for easy testing...")
        hardcoded_identity = LocalIdentity(seed=EXAMPLE_SEED)
        mesh_node, identity = create_mesh_node_with_identity(
            "LoginServer", radio_type, serial_port, hardcoded_identity
        )
    else:
        mesh_node, identity = create_mesh_node("LoginServer", radio_type, serial_port)

    # Get our public key info
    our_pub_key = identity.get_public_key()
    our_hash = our_pub_key[0]
    print(f"Server Identity: {our_pub_key.hex()}")
    print(f"Server Hash: 0x{our_hash:02X}")
    print()

    # Create ACL for managing authenticated clients
    acl = ClientACL(max_clients=32, admin_password=admin_password, guest_password=guest_password)

    def get_out_path(client_identity: Identity):
        client = acl.get_client(client_identity.get_public_key())
        if client is None or client.out_path_len < 0:
            return None
        return (bytes(client.out_path), client.out_path_len)

    def clear_out_path(client_identity: Identity):
        client = acl.get_client(client_identity.get_public_key())
        if client is not None:
            client.out_path_len = -1
            client.out_path = bytearray()

    # Create login server handler with authentication callback
    login_handler = LoginServerHandler(
        local_identity=identity,
        log_fn=lambda msg: print(msg),
        authenticate_callback=acl.authenticate_client,  # Delegate authentication to ACL
        get_out_path=get_out_path,
        clear_out_path=clear_out_path,
    )

    # Set up packet sending callback
    def send_packet_with_delay(packet, delay_ms: int):
        """Send a packet with a delay."""
        asyncio.create_task(delayed_send(packet, delay_ms))

    async def delayed_send(packet, delay_ms: int):
        """Send packet after delay."""
        await asyncio.sleep(delay_ms / 1000.0)
        try:
            await mesh_node.dispatcher.send_packet(packet, wait_for_ack=False)
        except Exception as e:
            print(f"Error sending response: {e}")

    login_handler.set_send_packet_callback(send_packet_with_delay)

    # Register the handler with the dispatcher
    mesh_node.dispatcher.register_handler(LoginServerHandler.payload_type(), login_handler)

    print("Login server started and listening...")
    print("   Waiting for login requests from clients...")
    print()
    print("Commands:")
    print("  - Press Ctrl+C to stop")
    print("  - Type 'status' to show ACL status")
    print("  - Type 'list' to list authenticated clients")
    print()

    # Command processor
    async def process_commands():
        """Process user commands."""
        import sys

        loop = asyncio.get_event_loop()

        while True:
            # Check for stdin input
            try:
                if sys.stdin.readable():
                    cmd = await loop.run_in_executor(None, sys.stdin.readline)
                    cmd = cmd.strip().lower()

                    if cmd == "status":
                        print(f"\nACL Status:")
                        print(
                            f"   Authenticated clients: {acl.get_num_clients()}/{acl.max_clients}"
                        )
                        print()

                    elif cmd == "list":
                        clients = acl.get_all_clients()
                        print(f"\n👥 Authenticated Clients ({len(clients)}):")
                        if not clients:
                            print("   <none>")
                        else:
                            for i, client in enumerate(clients, 1):
                                pub_key_hex = client.id.get_public_key()[:8].hex()
                                role = "ADMIN" if client.is_admin() else "GUEST"
                                print(f"   {i}. {pub_key_hex}... [{role}]")
                        print()

            except Exception:
                pass

            await asyncio.sleep(0.1)

    # Run command processor in background
    asyncio.create_task(process_commands())

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down login server...")
        print(f"   Final ACL size: {acl.get_num_clients()} clients")


def main():
    """Main function for running the example."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Run a login authentication server for the mesh network"
    )
    parser.add_argument(
        "--radio-type",
        choices=RADIO_TYPES,
        default="waveshare",
        help="Radio hardware type (default: waveshare)",
    )
    parser.add_argument(
        "--serial-port",
        default="/dev/ttyUSB0",
        help="Serial port for KISS TNC (default: /dev/ttyUSB0)",
    )
    parser.add_argument(
        "--admin-password",
        default=EXAMPLE_ADMIN_PASSWORD,
        help=f"Admin password (default: {EXAMPLE_ADMIN_PASSWORD})",
    )
    parser.add_argument(
        "--guest-password",
        default=EXAMPLE_GUEST_PASSWORD,
        help=f"Guest password (default: {EXAMPLE_GUEST_PASSWORD}, empty to disable)",
    )
    parser.add_argument(
        "--use-random-identity",
        action="store_true",
        help="Use random identity instead of hardcoded example identity",
    )

    args = parser.parse_args()

    print(f"Using {args.radio_type} radio configuration")
    if args.radio_type == "kiss-tnc":
        print(f"Serial port: {args.serial_port}")

    # Show the identity that will be used
    if not args.use_random_identity:
        # Create a temporary identity to show what the keys will be
        temp_identity = LocalIdentity(seed=EXAMPLE_SEED)
        temp_pubkey = temp_identity.get_public_key()
        print(f"Server Public Key: {temp_pubkey.hex()}")
        print(f"Server Hash: 0x{temp_pubkey[0]:02X}")
        print("(Use --use-random-identity to generate random keys instead)")

    try:
        asyncio.run(
            run_login_server(
                args.radio_type,
                args.serial_port,
                args.admin_password,
                args.guest_password,
                use_hardcoded_identity=not args.use_random_identity,
            )
        )
    except KeyboardInterrupt:
        print("\nExample terminated by user")


if __name__ == "__main__":
    main()
