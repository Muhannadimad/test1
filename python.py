import socket
import ssl
import logging
import argparse
import pprint
import sys
from datetime import datetime


# testtest

# from cryptography import x509
# from cryptography.hazmat.backends import default_backend

# Configure logging for SSL/TLS debug output
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


def perform_handshake(ssl_sock):
    # Perform SSL/TLS handshake
    start_time = datetime.now()
    try:
        ssl_sock.do_handshake()
    except ssl.SSLError as e:
        # Handle SSL/TLS handshake errors
        logging.error(f"SSL/TLS handshake error: {e}")
    else:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds() * 1000
        logging.info(
            f"SSL/TLS handshake was successfully completed in {duration:.2f} ms"
        )


def print_server_details(ssl_sock):
    logging.info(f"Server Host Name: {ssl_sock.server_hostname}")
    logging.info(f"IP address and Port: {ssl_sock.getpeername()}")


def print_tls_connection_details(ssl_sock):
    # Access SSL/TLS connection details
    cipher = ssl_sock.cipher()
    tls_version = ssl_sock.version()
    logging.info(f"SSL/TLS version: {tls_version}")
    logging.info(f"Cipher used: {cipher}")


def print_server_cert_details(ssl_sock):
    ssl_info = ssl_sock.getpeercert()
    keys_to_check = [
        "caIssuers",
        "issuer",
        "subject",
        "notBefore",
        "notAfter",
        "OCSP",
        "crlDistributionPoints",
        "serialNumber",
    ]

    for key in keys_to_check:
        try:
            value = ssl_info[key]
            logging.info(f"{key}: {value}")
        except KeyError:
            logging.warning(f"{key} not found in the SSL certificate.")

    subject_alt_names = ssl_sock.getpeercert()["subjectAltName"]
    if subject_alt_names:
        logging.info("SubjectAltName entries:")
        for i, entry in enumerate(subject_alt_names):
            print(f"  - {entry}")


def main():

    parser = argparse.ArgumentParser(description="SSL/TLS Debugging Script")
    parser.add_argument("hostname", help="Hostname of the SSL/TLS server")
    parser.add_argument(
        "--port",
        type=int,
        nargs="?",
        default=443,
        help="Port number of the SSL/TLS server",
    )
    args = parser.parse_args()

    # Set up a TCP socket

    hostname = args.hostname
    port = args.port
    try:

        sock = socket.create_connection((hostname, port))
    except socket.error as e:
        logging.error(f"Socket connection error: {e}")
        # Handle the error as needed (exit, log, etc.)
        sys.exit(1)

    # Wrap the socket with SSL/TLS
    context = ssl.create_default_context()
    context.set_ciphers("ALL")  # Enable all ciphers for detailed logging
    ssl_sock = context.wrap_socket(sock, server_hostname=hostname)

    # using x509 but not very useful
    # end_entity_cert_data = ssl_sock.getpeercert(binary_form=True)
    # end_entity_cert = x509.load_der_x509_certificate(end_entity_cert_data, default_backend())
    # logging.info(f"End-Entity Certificate:\n{end_entity_cert}")
    # logging.info(f"info:{end_entity_cert.issuer}")
    # logging.info(f"info:{end_entity_cert.subject}")
    # logging.info(f"info:{end_entity_cert.extensions}")
    print("[HANDSHAKING]")
    perform_handshake(ssl_sock)
    print("\n")
    print("[SERVER INFO]")
    print_server_details(ssl_sock)
    print("\n")
    print("[DETAILED SSL/TLS CONNECTION INFORMATION]")
    print_tls_connection_details(ssl_sock)
    print("\n")
    print("[SERVER CERTIFICATE INFORMATION]")
    print_server_cert_details(ssl_sock)
    print("\n")
    print("SSL/TLS INSPECTION COMPLETED SUCCESSFULLY")
    # Close the SSL/TLS socket
    ssl_sock.close()


if __name__ == "__main__":
    main()
