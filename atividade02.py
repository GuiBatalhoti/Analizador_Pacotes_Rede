#Feito por Guilherme Eduardo Silva Batalhoti

#importando os pacotes necessários
import socket
import struct
import datetime
import matplotlib.pyplot as plt


# extraindo as informações sobre o cabeçalgo da camada transporte
def descompactanto_painel_rede(dados):
    # descompactando o endereço MAC do sender e do reciver, além do protocolo
    #"! 6s 6s H" --> '6s' string de 6 carateres; 'H' unsing int
    #dados[:14] --> desconsiderando os 14 primeiros bytes
    dest_mac_addr, fonte_mac_addr, protocolo = struct.unpack("! 6s 6s H", dados[:14])
    return get_mac_addr(dest_mac_addr), get_mac_addr(fonte_mac_addr), socket.htons(protocolo), dados[14:]


# retorna o endereço MAC formatado de forma correta (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    #formatando os bytes para pares de valores Hexadecimais
    bytes_str = map('{:02x}'.format, bytes_addr)
    
    # formatando a string de bytes para o formato padrão
    endereco = ':'.join(bytes_str).upper()
    return endereco


# retorna as informações cabeçalho IPv4
def cabecalho_ipv4(dados):
    #pegando a versão e o tamanho do cabeçalho
    versao_tamanho_cabecalho = dados[0]
    versao = versao_tamanho_cabecalho >> 4
    tamanho_cabecalho = (versao_tamanho_cabecalho & 15) * 4

    #pegando o outro valores do cabeçalho
    tempo_vida, protocolo, fonte, destino = struct.unpack('! 8x B B 2x 4s 4s', dados[:20])

    return versao, tamanho_cabecalho, tempo_vida, protocolo, formata_ipv4(fonte), formata_ipv4(destino), dados[tamanho_cabecalho:]


# formata o IPv4 com o padrão
def formata_ipv4(addr):
    return '.'.join(map(str, addr))


# pega informações do cabeçalho de TCP
def cabecalho_TPC(dados):
    #extraindo dados do cabeçalho TCP
    #flags --> não utilizado
    (porta_fonte, porta_dest, sequencia, reconhecimento, offset_reversed_flags) = struct.unpack('! H H L L H', dados[:14])
    offset = (offset_reversed_flags >> 12) * 4
    return porta_fonte, porta_dest, sequencia, reconhecimento, dados[offset:]


# pega informações do cabeçalho de UDP
def cabecalho_UDP(dados):
    #extraindo dados do cabeçalho UDP
    porta_fonte, porta_dest, tamanho = struct.unpack('! H H 2x H', dados[:8])
    return porta_fonte, porta_dest, tamanho


#faz um loop esperando pelos pacotes da rede chegarem
def main():
    
    #ficar no loop por 60 segundos
    tempo_final = datetime.datetime.now() + datetime.timedelta(seconds=60)

    #portas dos protocolos
    portas_protocolos =  {
        21: 'FTP',
        22: 'SSH',
        23: 'TELNET',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS'
    }

    #número de vezes que cada protocolo identificado
    qtd_protolocos = {
        21: 0,
        22: 0, 
        23: 0,
        25: 0,
        53: 0,
        80: 0,
        110: 0,
        143: 0,
        443: 0
    }

    #abrindo um socket para pegar os dados da rede
    soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    #loop por 60 segundos para pegar qualquer pacote que possa passar pela rede
    while datetime.datetime.now() < tempo_final:
    
        #dados recebidos e endereco de onde foram enviados os dados
        dados_compactados, endereco = soc.recvfrom(65536) #tamanho do buffer

        #descompactando os dados recebidos
        dest_mac_addr, fonte_mac_addr, protocolo_transmissao, dados = descompactanto_painel_rede(dados_compactados)

        #mostando os endereços MAC de origem e Destino
        print('\nRede:')
        print('Mac destino: {}, MAC Fonte: {}, Protocolo: {}'.format(dest_mac_addr, fonte_mac_addr, protocolo_transmissao))

        # se for um pacote IPv4
        if protocolo_transmissao == 8:

            #descompactando os dados de IPv4
            versao, tamanho_cabecalho, tempo_vida, proto, ip_fonte, ip_destino, dados = cabecalho_ipv4(dados)

            #mostrando os dados IPv4
            print('IPv4:')
            print('\tVersao: {}, Tamanho: {}, Tempo de Vida: {}'.format(versao, tamanho_cabecalho, tempo_vida))
            print('\tProtocolo: {}, IP de Origem e Destino: {} : {}'.format(proto, ip_fonte, ip_destino))

            #Identificando do tipo de protocolo de transporte: TCP == 6 ou UDP == 8
            if proto == 6:
                porta_fonte, porta_dest, sequencia, reconhecimento, dados = cabecalho_TPC(dados)

                print('\n\tTCP:')
                print('\t\tPorta de Origem e Destino: {} : {}'.format(porta_fonte, porta_dest))
                print('\t\tSequência: {}, Reconhecimento: {}'.format(sequencia, reconhecimento))
            
            if proto == 17:
                porta_fonte, porta_dest, tamanho = cabecalho_UDP(dados)

                print('\n\tUDP:')
                print('\t\tPorta de Origem e Destino: {} : {}'.format(porta_fonte, porta_dest))
                print('\t\tTamanho: {}'.format(tamanho))
            
            # Identificando o protocolo de aplicação e adicionando na lista
            if (porta_dest in portas_protocolos):
                print('\t\tDestino: {}'.format(portas_protocolos[porta_dest]))
                qtd_protolocos[porta_dest] += 1
            elif (porta_fonte in portas_protocolos):
                print('\t\tOrigem: {}'.format(portas_protocolos[porta_fonte]))
                qtd_protolocos[porta_fonte] += 1

            #Mostrando os dados que foram pegos e tentando decodificar para 'ascii', se não imprimir na forma bruta
            try:
                print('\tDados:')
                print('\t\t' + str(dados.decode('ascii')))
            except:
                print('\tDados:')
                print('\t\t' + str(dados))

    
    #colocando a quantificação encontrada em um gráfico
    plt.bar(portas_protocolos.values(), qtd_protolocos.values())
    plt.show()
    

main()