
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


# Converte cada número para string e junta-os com um espaço
cryptogram = [43, 23, 15, 120, 126, 113, 255, 8, 249, 184, 228, 52, 68, 171, 159, 88, 40, 61, 209, 192, 169, 122, 158, 139, 172, 55, 16, 117, 108, 54, 153, 175, 102, 26, 206, 27, 42, 195, 165, 14, 114, 254, 73, 32, 130, 112, 17, 195]

# --- Dados de Exemplo (Criptograma e IV de 16 bytes) ---
# iv = bytes(cryptogram[0:16])
iv = bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
criptograma = bytes(cryptogram[16:48])
count = 0
for i in range(256):
    # chave_16bytes= bytes([i,i,i,i,i,i,i,i,i,i,i,i,i,i,i,i])

    for j in range(256):   
        chave_16bytes= bytes([i,j,i,j,i,j,i,j,i,j,i,j,i,j,i,j])

        count+=1
        try:
            # 2. Configurar o decifrador AES com a chave atual
            # cipher = Cipher(algorithms.AES(chave_16bytes), modes.CBC(iv))
            cipher = Cipher(algorithms.AES(chave_16bytes), modes.ECB()) 
            decryptor = cipher.decryptor()
            
            # 3. Tentar decifrar o bloco
            texto_decifrado = decryptor.update(criptograma) + decryptor.finalize()

            # Remove o padding PKCS7
            unpadder = padding.PKCS7(128).unpadder() # 128 bits é o tamanho do bloco AES
            texto_limpo = unpadder.update(texto_decifrado) + unpadder.finalize()
            
        
            if all(0 <= b <= 126 for b in texto_limpo):  # printable + tab/newline/CR 
                print(f'\n{count}')
                # print(f"[+] Chave Encontrada! Byte em decimal: {i,j} (Hex: {hex(i,j)})")
                print(f"[+] Chave completa (16 bytes): {chave_16bytes}")
                print(f"[+] Texto decifrado: {texto_limpo.decode('utf-8', errors='ignore')}")
                break
                
        except Exception:
            # Ignora erros de padding ou decifragem incorreta e continua para o próximo byte
            continue