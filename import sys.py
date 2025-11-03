import sys
import base64
from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def parse_input_bytes(s: str) -> bytes:
    """Interpreta entrada como hex (con prefijo) o texto UTF-8"""
    s = s.strip()
    if not s:
        return b''
    if s.lower().startswith("hex:"):
        return bytes.fromhex(s[4:].strip())
    if s.lower().startswith("0x"):
        return bytes.fromhex(s[2:].strip())
    return s.encode('utf-8')

def prepare_key(key_bytes: bytes, required_len: int) -> bytes:
    """Ajusta la clave al tamaño requerido"""
    if len(key_bytes) < required_len:
        needed = required_len - len(key_bytes)
        key_bytes = key_bytes + get_random_bytes(needed)
    elif len(key_bytes) > required_len:
        key_bytes = key_bytes[:required_len]
    return key_bytes

def prepare_3des_key(key_bytes: bytes) -> bytes:
    """Prepara clave para 3DES (24 bytes)"""
    return prepare_key(key_bytes, 24)

def ensure_iv(iv_bytes: bytes, required_len: int) -> bytes:
    """Ajusta o genera IV según sea necesario"""
    if not iv_bytes:
        iv_bytes = get_random_bytes(required_len)
    elif len(iv_bytes) < required_len:
        iv_bytes = iv_bytes + get_random_bytes(required_len - len(iv_bytes))
    elif len(iv_bytes) > required_len:
        iv_bytes = iv_bytes[:required_len]
    return iv_bytes

def encrypt_decrypt_des(plaintext: bytes, key: bytes, iv: bytes):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, DES.block_size))
    decipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(decipher.decrypt(ct), DES.block_size)
    return ct, pt

def encrypt_decrypt_3des(plaintext: bytes, key: bytes, iv: bytes):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, DES3.block_size))
    decipher = DES3.new(key, DES3.MODE_CBC, iv)
    pt = unpad(decipher.decrypt(ct), DES3.block_size)
    return ct, pt

def encrypt_decrypt_aes256(plaintext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    decipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(decipher.decrypt(ct), AES.block_size)
    return ct, pt

def main():
    print("=== CIFRADO SIMETRICO (DES, 3DES, AES-256) - MODO CBC ===")
    
    # Selección de algoritmo
    alg = input("Algoritmo (DES/3DES/AES): ").strip().upper()
    if alg not in ("DES", "3DES", "AES"):
        print("Algoritmo no valido")
        sys.exit(1)

    # Entrada de datos
    print("\n--- Entrada de datos ---")
    key_in = input("Clave (texto o hex:...): ")
    iv_in = input("IV (texto o hex:...): ")
    text_in = input("Texto a cifrar: ")

    # Procesamiento
    key_bytes = parse_input_bytes(key_in)
    iv_bytes = parse_input_bytes(iv_in)
    plaintext = text_in.encode('utf-8')

    # Configuración por algoritmo
    try:
        if alg == "DES":
            key_final = prepare_key(key_bytes, 8)
            iv_final = ensure_iv(iv_bytes, 8)
            ct, pt = encrypt_decrypt_des(plaintext, key_final, iv_final)
            
        elif alg == "3DES":
            key_final = prepare_3des_key(key_bytes)
            iv_final = ensure_iv(iv_bytes, 8)
            ct, pt = encrypt_decrypt_3des(plaintext, key_final, iv_final)
            
        else:  # AES
            key_final = prepare_key(key_bytes, 32)
            iv_final = ensure_iv(iv_bytes, 16)
            ct, pt = encrypt_decrypt_aes256(plaintext, key_final, iv_final)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Resultados
    print("\n--- Resultados ---")
    print(f"Algoritmo: {alg}")
    print(f"Clave final: {key_final.hex()}")
    print(f"IV final: {iv_final.hex()}")
    print(f"Texto original: {plaintext.decode('utf-8')}")
    print(f"Texto cifrado (Base64): {base64.b64encode(ct).decode('ascii')}")
    print(f"Texto cifrado (Hex): {ct.hex()}")
    print(f"Texto descifrado: {pt.decode('utf-8')}")
    
    # Verificación
    if pt == plaintext:
        print("Verificacion: OK")
    else:
        print("Verificacion: ERROR")

if __name__ == "__main__":
    main()