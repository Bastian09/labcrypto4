
from pathlib import Path

from scapy.all import rdpcap, Raw
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CARPETA = Path(__file__).resolve().parent

# Leer clave privada
with open(CARPETA / "clave_privada.pem", "rb") as f:
    clave_privada = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# Leer captura
paquetes = rdpcap(str(CARPETA / "transacciones_cifradas.pcap"))

# Obtener datos de aplicación de los paquetes
datos = []

for numero, paquete in enumerate(paquetes, 1):
    if Raw in paquete:
        datos.append((numero, bytes(paquete[Raw].load)))

# Buscar el paquete RSA
marcador_rsa = b"RSA_PIN|"
salt = None
pin_cifrado = None

tam_rsa = clave_privada.key_size // 8

for numero, payload in datos:
    posicion = payload.find(marcador_rsa)

    if posicion == -1:
        continue

    inicio = posicion + len(marcador_rsa)

    salt = payload[inicio:inicio + 16]
    pin_cifrado = payload[
        inicio + 16:inicio + 16 + tam_rsa
    ]

    if len(salt) != 16 or len(pin_cifrado) != tam_rsa:
        raise ValueError("Paquete RSA incompleto")

    print("Paquete RSA encontrado:", numero)
    break

if pin_cifrado is None:
    raise ValueError("No se encontro RSA_PIN")
print("\n=== DIAGNOSTICO RSA ===")
print("Salt (hex):", salt.hex())
print("Longitud salt:", len(salt))
print("Longitud PIN cifrado:", len(pin_cifrado))
print("Tamano clave RSA:", clave_privada.key_size)
print("PIN cifrado (primeros 32 bytes):", pin_cifrado[:32].hex())
print("=======================\n")

# Recuperar PIN mediante RSA-OAEP
pin_bytes = clave_privada.decrypt(
    pin_cifrado,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

pin = pin_bytes.decode("utf-8")

print("PIN recuperado:", pin)

if len(pin) != 4 or not pin.isdigit():
    raise ValueError("El PIN recuperado no tiene 4 digitos")

# Derivar clave AES mediante Scrypt
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1
)

clave_aes = kdf.derive(pin_bytes)
aesgcm = AESGCM(clave_aes)

# Descifrar transacciones
marcador_aes = b"AESGCM|"
transacciones = []

for numero, payload in datos:
    posicion = payload.find(marcador_aes)

    if posicion == -1:
        continue

    inicio = posicion + len(marcador_aes)

    nonce = payload[inicio:inicio + 12]
    cifrado = payload[inicio + 12:]

    if len(nonce) != 12 or len(cifrado) < 16:
        print("Paquete incompleto:", numero)
        continue

    try:
        mensaje = aesgcm.decrypt(
            nonce,
            cifrado,
            None
        )

        texto = mensaje.decode("utf-8")
        transacciones.append(texto)

    except Exception as error:
        print("Error en paquete", numero, type(error).__name__)

print("\nTransacciones recuperadas:",
      len(transacciones))

for indice, texto in enumerate(transacciones, 1):
    print(f"\n[Transaccion {indice}]")
    print(texto)
