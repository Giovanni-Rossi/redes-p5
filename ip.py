from grader.tcputils import calc_checksum, str2addr
from iputils import *
import struct
import random
import socket

ICMP_TYPE_TIME_EXCEEDED = 11
ICMP_CODE_TTL_EXPIRED = 0

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
        src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            # Atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # Atua como roteador
            if ttl <= 1: 
                # Descartar o datagrama se o TTL for 0 ou 1
                print("Datagrama descartado: TTL expirado.")
                self._send_icmp_time_exceeded(src_addr, datagrama)
                return None
            else:
                # Decrementa o TTL
                ttl -= 1

                # Converte os endereços IP para o formato de bytes
                src_addr_bytes = str2addr(src_addr)
                dst_addr_bytes = str2addr(dst_addr)

                # Calcula o comprimento total do datagrama (cabeçalho + payload)
                total_length = 20 + len(payload)

                # Cabeçalho IP sem checksum
                header = struct.pack('!BBHHHBBH4s4s',
                                    (4 << 4) | 5, 0, total_length, identification,
                                    0, ttl, proto, 0,
                                    src_addr_bytes, dst_addr_bytes)

                # Calcula o checksum do cabeçalho IP
                checksum = calc_checksum(header)

                # Cabeçalho com o checksum correto
                header = struct.pack('!BBHHHBBH4s4s',
                                    (4 << 4) | 5, 0, total_length, identification,
                                    0, ttl, proto, checksum,
                                    src_addr_bytes, dst_addr_bytes)

                # Cria o novo datagrama com o cabeçalho atualizado
                new_datagrama = header + payload

                # Determina o próximo salto
                next_hop = self._next_hop(dst_addr)

                # Encaminha o datagrama para o próximo roteador
                self.enlace.enviar(new_datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # Converte o dest_addr para uma string de bits
        dest_addr_bits = ''.join(f'{int(octeto):08b}' for octeto in dest_addr.split('.'))
        
        best_match = None
        max_prefix_length = -1

        # Itera sobre a tabela de encaminhamento
        for cidr, next_hop in self.tabela_encaminhamento:
            # Separa a parte da rede e a máscara do CIDR
            rede, prefixo = cidr.split('/')
            prefixo = int(prefixo)
            
            # Converte a rede para bits
            rede_bits = ''.join(f'{int(octeto):08b}' for octeto in rede.split('.'))
            
            # Compara os primeiros `prefixo` bits
            if rede_bits[:prefixo] == dest_addr_bits[:prefixo]:
                # Verifica se o prefixo é o mais longo encontrado até agora
                if prefixo > max_prefix_length:
                    max_prefix_length = prefixo
                    best_match = next_hop

        return best_match


       

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela_encaminhamento = tabela
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, proto=IPPROTO_TCP):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        # Versão e IHL (Internet Header Length)
        version_ihl = (4 << 4) | 5
        
        # Tipo de serviço
        tos = 0
        
        # Tamanho total (header + data)
        total_length = 20 + len(segmento)
        
        # Identificação
        identification = random.randint(0, 65535)
        
        # Flags e Fragment Offset
        flags_fragment_offset = 0
        
        # Tempo de vida (TTL)
        ttl = 64
        
        # Protocolo (TCP)
        protocol = proto
        
        # Endereço de origem (assumindo que self.meu_endereco existe e é um endereço IP válido)
        src_addr = socket.inet_aton(self.meu_endereco)
        
        # Endereço de destino
        dst_addr = socket.inet_aton(dest_addr)
        
        # Cabeçalho sem o checksum
        header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, identification, 
                             flags_fragment_offset, ttl, protocol, 0, src_addr, dst_addr)
        
        # Calculando o checksum do cabeçalho IP
        checksum = calc_checksum(header)
        
        # Cabeçalho com o checksum correto
        header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_length, identification, 
                             flags_fragment_offset, ttl, protocol, checksum, src_addr, dst_addr)
        
        # Montando o datagrama IP completo
        datagrama = header + segmento
        
        # Encontrar o próximo salto
        next_hop = self._next_hop(dest_addr)
        
        # Enviar datagrama pela camada de enlace
        self.enlace.enviar(datagrama, next_hop)
    
    def _send_icmp_time_exceeded(self, src_addr, original_datagrama):
        """
        Envia uma mensagem ICMP Time Exceeded de volta ao remetente.
        """
        # Cabeçalho ICMP Time Exceeded
        icmp_header = struct.pack('!BBHI', ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TTL_EXPIRED, 0, 0)

        # Os primeiros 8 bytes do cabeçalho IP original + 8 bytes do payload original
        icmp_payload = original_datagrama[:28]

        # Calcula o checksum ICMP
        checksum = calc_checksum(icmp_header + icmp_payload)
        icmp_header = struct.pack('!BBHI', ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TTL_EXPIRED, checksum, 0)

        # Cria o datagrama ICMP completo
        icmp_message = icmp_header + icmp_payload

        # Cabeçalho IP para a mensagem ICMP
        src_addr_bytes = str2addr(self.meu_endereco)
        dst_addr_bytes = str2addr(src_addr)
        total_length = 20 + len(icmp_message)
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                (4 << 4) | 5, 0, total_length, 0,
                                0, 64, 1, 0,  # 64 é um valor típico de TTL, 1 é o protocolo ICMP
                                src_addr_bytes, dst_addr_bytes)

        # Calcula o checksum do cabeçalho IP
        ip_checksum = calc_checksum(ip_header)
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                (4 << 4) | 5, 0, total_length, 0,
                                0, 64, 1, ip_checksum,
                                src_addr_bytes, dst_addr_bytes)

        # Cria o datagrama IP completo com a mensagem ICMP
        icmp_datagrama = ip_header + icmp_message

        # Envia o datagrama ICMP de volta ao remetente
        next_hop = self._next_hop(src_addr)
        self.enlace.enviar(icmp_datagrama, next_hop)