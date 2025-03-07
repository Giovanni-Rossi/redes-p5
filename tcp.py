import asyncio
from time import time
from grader.tcputils import FLAGS_ACK, FLAGS_FIN, FLAGS_SYN, MSS, fix_checksum, make_header
from tcputils import *


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload_data = segment[4*(flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            ack_no = seq_no + 1
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, ack_no)
            response_flags = FLAGS_SYN + FLAGS_ACK
            resposta_segmento = fix_checksum(make_header(dst_port, src_port, seq_no, ack_no, response_flags), src_addr, dst_addr)
            self.rede.enviar(resposta_segmento, src_addr)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload_data)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = None

        
        self.seq_no = seq_no
        self.ack_no = ack_no
        self.ack_client = ack_no
        self.seq_client = ack_no
        self.sent_data = {}
        self.segments = {}
        self.SampleRTT = 0
        self.DevRTT = 0
        self.EstimatedRTT = 0
        self.TimeoutInterval = 1
        self.SentTime = 0
        self.cwnd = MSS
        self.rcv_cwnd = 0
        self.reenvio = False
        self.open = True
        

    def _exemplo_timer(self):
        self.reenvio = True
        self.cwnd = ((self.cwnd // MSS) // 2) * MSS
        self.enviar(self.sent_data[list(self.sent_data.keys())[0]])

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if len(self.sent_data):
            if not self.reenvio:
                first = self.SampleRTT == 0
                self.SampleRTT = time() - self.SentTime
                if first:
                    self.EstimatedRTT = self.SampleRTT
                    self.DevRTT = self.SampleRTT / 2
                else:
                    self.EstimatedRTT = 0.875 * self.EstimatedRTT + 0.125 * self.SampleRTT
                    self.DevRTT = 0.75 * self.DevRTT + 0.25 * abs(self.SampleRTT - self.EstimatedRTT)
                self.TimeoutInterval = self.EstimatedRTT + 4 * self.DevRTT

            if ack_no > list(self.sent_data.keys())[0]:
                y = list(self.sent_data.keys())[0]
                while y < ack_no:
                    self.rcv_cwnd += len(self.segments[y])
                    del self.segments[y]
                    del self.sent_data[y]
                    if len(self.sent_data) == 0:
                        break
                    y = list(self.sent_data.keys())[0]

                if len(self.sent_data):
                    if self.timer is not None:
                        self.timer.cancel()
                    self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
                else:
                    self.timer.cancel()

                if self.rcv_cwnd >= self.cwnd or len(self.sent_data) == 0:
                    self.cwnd += MSS
                    self.rcv_cwnd = 0
                    if len(self.sent_data):
                        if self.timer is not None:
                            self.timer.cancel()
                        self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
                        self.enviar(self.sent_data[list(self.sent_data.keys())[0]])

        self.reenvio = False

        if seq_no != self.ack_no or (len(payload) == 0 and (flags & FLAGS_FIN) != FLAGS_FIN) or not self.open:
            return

        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        self.seq_no = self.ack_no
        self.ack_no += len(payload)
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_no += 1
        self.ack_client = self.ack_no
        self.callback(self, payload)
        flags = FLAGS_ACK
        new_segment = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, flags), src_addr, dst_addr)
        self.servidor.rede.enviar(new_segment, src_addr)

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.fechar()

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        if not self.open:
            return

        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        index = 0

        if len(self.sent_data) == 0:
            while index < len(dados):
                payload = dados[index:index + MSS]
                flags = FLAGS_ACK
                self.sent_data[self.seq_client] = payload
                segmento_novo = fix_checksum(make_header(dst_port, src_port, self.seq_client, self.ack_no, flags) + payload, src_addr, dst_addr)
                self.segments[self.seq_client] = segmento_novo
                self.seq_client += len(payload)
                index += MSS

        contador = 0
        if not self.reenvio:
            for seq in self.sent_data.keys():
                if contador >= self.cwnd:
                    break
                self.servidor.rede.enviar(self.segments[seq], src_addr)
                contador += len(self.segments[seq])
        else:
            primeiro_item = list(self.sent_data.keys())[0]
            self.servidor.rede.enviar(self.segments[primeiro_item], src_addr)

        self.SentTime = time()
        if self.timer is not None:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)

    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        self.callback(self, b'')
        flags = FLAGS_FIN
        segmento_novo = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, flags), src_addr, dst_addr)
        self.servidor.rede.enviar(segmento_novo, src_addr)
        self.open = False
