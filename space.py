import os
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Função para gerar um par de chaves RSA e salvar em arquivos
def gerar_par_de_chaves(nome_sonda):
    chave_privada = RSA.generate(2048)
    chave_publica = chave_privada.publickey()

    with open(f'{nome_sonda.lower()}.private.pem', 'wb') as arquivo_privado:
        arquivo_privado.write(chave_privada.exportKey('PEM'))

    with open(f'{nome_sonda.lower()}.public.pem', 'wb') as arquivo_publico:
        arquivo_publico.write(chave_publica.exportKey('PEM'))

# Função para enviar a chave pública da sonda para o servidor
def enviar_chave_publica(nome_sonda):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente_socket:
        cliente_socket.connect(('127.0.0.1', 8080))
        chave_publica = open(f'{nome_sonda.lower()}.public.pem', 'rb').read()
        cliente_socket.send(chave_publica)

# Função para coletar dados da sonda e criptografá-los com AES
def coletar_e_criptografar_dados(nome_sonda):
    local = input("Local: ")
    temperatura = input("Temperatura: ")
    radiacao_alfa = input("Radiação Alfa: ")
    radiacao_beta = input("Radiação Beta: ")
    radiacao_gama = input("Radiação Gama: ")

    dados = f"Local: {local}\nTemperatura: {temperatura} º\nRadiação Alfa: {radiacao_alfa}\nRadiação Beta: {radiacao_beta}\nRadiação Gama: {radiacao_gama}"

    chave_aes = os.urandom(16)
    cifra = AES.new(chave_aes, AES.MODE_EAX)
    ciphertext, tag = cifra.encrypt_and_digest(dados.encode())

    with open(f'{local.replace(" ", "").lower()}{data_atual()}.txt', 'wb') as arquivo_dados:
        arquivo_dados.write(cifra.nonce)
        arquivo_dados.write(tag)
        arquivo_dados.write(ciphertext)

# Função para gerar uma assinatura dos dados coletados
def gerar_assinatura(nome_sonda):
    nome_arquivo = input("Nome do arquivo de dados: ")
    with open(f'{nome_arquivo}.txt', 'rb') as arquivo_dados:
        dados = arquivo_dados.read()
    
    chave_privada = RSA.import_key(open(f'{nome_sonda.lower()}.private.pem', 'rb').read())
    hash_dados = SHA256.new(dados)
    assinatura = pkcs1_15.new(chave_privada).sign(hash_dados)

    with open(f'{nome_arquivo}assinatura', 'wb') as arquivo_assinatura:
        arquivo_assinatura.write(assinatura)

# Função para enviar dados e assinatura para o servidor
def enviar_dados_e_assinatura(nome_sonda):
    nome_arquivo = input("Nome do arquivo de dados: ")
    with open(f'{nome_arquivo}.txt', 'rb') as arquivo_dados:
        dados = arquivo_dados.read()
    with open(f'{nome_arquivo}assinatura', 'rb') as arquivo_assinatura:
        assinatura = arquivo_assinatura.read()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente_socket:
        cliente_socket.connect(('127.0.0.1', 8080))
        cliente_socket.send(dados)
        cliente_socket.send(assinatura)

# Função para verificar a assinatura com a chave pública da sonda
def verificar_assinatura(chave_publica_sonda, dados, assinatura):
    chave_publica = RSA.import_key(chave_publica_sonda)
    hash_dados = SHA256.new(dados)
    try:
        pkcs1_15.new(chave_publica).verify(hash_dados, assinatura)
        return True
    except (ValueError, TypeError):
        return False

# Função para lidar com a conexão do servidor
# Função para lidar com a conexão do servidor
def lidar_com_conexao(cliente_socket):
    with cliente_socket:
        opcao_bytes = cliente_socket.recv(1)
        if not opcao_bytes:
            return  # Lidar com uma conexão fechada
        opcao = opcao_bytes.decode('utf-8', errors='replace')  # Substituir caracteres inválidos
        
        if opcao == '2':
            nome_sonda = input("Nome da sonda: ")
            enviar_chave_publica(nome_sonda)
        elif opcao == '5':
            nome_arquivo = input("Nome do arquivo de dados: ")
            chave_publica_sonda = open(f'{nome_sonda.lower()}.public.pem', 'rb').read()
            dados = cliente_socket.recv(4096)
            assinatura = cliente_socket.recv(256)
            
            if verificar_assinatura(chave_publica_sonda, dados, assinatura):
                print("Arquivo recebido com sucesso e a assinatura é válida.")
                # Salvar os dados em um arquivo se necessário
                with open(f'{nome_arquivo}.txt', 'wb') as arquivo_dados:
                    arquivo_dados.write(dados)
            else:
                print("Arquivo inválido.")


# Função para obter a data atual no formato especificado
def data_atual():
    from datetime import datetime
    return datetime.now().strftime("%d.%m")

# Função principal que apresenta o menu de opções
def main():
    while True:
        print("\nMenu de Opções:")
        print("1 – Cadastrar Sonda e Gerar Par de Chaves")
        print("2 – Enviar Chave da Sonda")
        print("3 – Coletar Dados da Sonda")
        print("4 – Gerar Assinatura dos Dados Coletados")
        print("5 – Enviar para a Terra os Dados")
        opcao = input("Escolha uma opção (1/2/3/4/5): ")

        if opcao == '1':
            nome_sonda = input("Nome da Sonda: ")
            gerar_par_de_chaves(nome_sonda)
        elif opcao == '2':
            nome_sonda = input("Nome da Sonda: ")
            enviar_chave_publica(nome_sonda)
        elif opcao == '3':
            nome_sonda = input("Nome da Sonda: ")
            coletar_e_criptografar_dados(nome_sonda)
        elif opcao == '4':
            nome_sonda = input("Nome da Sonda: ")
            gerar_assinatura(nome_sonda)
        elif opcao == '5':
            nome_sonda = input("Nome da Sonda: ")
            enviar_dados_e_assinatura(nome_sonda)

# Função para criar e iniciar um servidor para receber conexões
def iniciar_servidor():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor_socket:
        servidor_socket.bind(('127.0.0.1', 8080))
        servidor_socket.listen()
        print("Servidor ouvindo em 127.0.0.1:8080")
        while True:
            cliente_socket, _ = servidor_socket.accept()
            print("Conexão recebida do cliente.")
            threading.Thread(target=lidar_com_conexao, args=(cliente_socket,)).start()


if __name__ == "__main__":
    # Iniciar o servidor em uma thread separada
    servidor_thread = threading.Thread(target=iniciar_servidor)
    servidor_thread.daemon = True 
    
    servidor_thread.start()
 
    # Executar o menu principal
    main()