class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)

class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        
        #Atributos criados
        self.escaped = []
        self.buffer = []

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        # Constantes SLIP
        SLIP_END = 0xC0
        SLIP_ESC = 0xDB
        SLIP_ESC_END = 0xDC
        SLIP_ESC_ESC = 0xDD

        # Adiciona o byte delimitador no início
        quadro = bytes([SLIP_END])

        # Processa o datagrama para aplicar as sequências de escape
        for byte in datagrama:
            if byte == SLIP_END:
                # Substitui 0xC0 por 0xDB 0xDC
                quadro += bytes([SLIP_ESC, SLIP_ESC_END])
            elif byte == SLIP_ESC:
                # Substitui 0xDB por 0xDB 0xDD
                quadro += bytes([SLIP_ESC, SLIP_ESC_ESC])
            else:
                # Caso contrário, insere o byte original
                quadro += bytes([byte])

        # Adiciona o byte delimitador no final
        quadro += bytes([SLIP_END])

        # Envia o quadro pela linha serial
        self.linha_serial.enviar(quadro)
    def __raw_recv(self, dados):
        # TODO: Preencha aqui com o código para receber dados da linha serial.
        # Trate corretamente as sequências de escape. Quando ler um quadro
        # completo, repasse o datagrama contido nesse quadro para a camada
        # superior chamando self.callback. Cuidado pois o argumento dados pode
        # vir quebrado de várias formas diferentes - por exemplo, podem vir
        # apenas pedaços de um quadro, ou um pedaço de quadro seguido de um
        # pedaço de outro, ou vários quadros de uma vez só.
        pass
    # Constantes SLIP
        SLIP_END = 0xC0
        SLIP_ESC = 0xDB
        SLIP_ESC_END = 0xDC
        SLIP_ESC_ESC = 0xDD

        for byte in dados:
            if byte == SLIP_END:
                # Verifica se o buffer contém um datagrama completo
                if self.buffer:
                    try:
                        # Repassa o datagrama completo para a camada superior, se não estiver vazio
                        if len(self.buffer) > 0:
                            self.callback(bytes(self.buffer))
                    except:
                        import traceback
                        traceback.print_exc()
                    finally:   
                        # Limpa o buffer para o próximo quadro
                        self.buffer.clear()
                continue

            if self.escaped:
                # Trata a sequência de escape
                if byte == SLIP_ESC_END:
                    self.buffer.append(SLIP_END)
                elif byte == SLIP_ESC_ESC:
                    self.buffer.append(SLIP_ESC)
                self.escaped = False
            elif byte == SLIP_ESC:
                # Indica que o próximo byte é parte de uma sequência de escape
                self.escaped = True
            else:
                # Byte normal, adiciona ao buffer
                self.buffer.append(byte)
