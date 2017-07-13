import base64
import hashlib
import random
import socket
import ssl
import urllib
import urllib.parse
import re


class MessageCodec:
    """
    A message codec is able to encode en decode data. The identity should
    always be preserved; I.e, msg == codec.decode(codec.encode(msg)).
    """

    def encode(self, data: tuple) -> bytes:
        """
        Encode the data to bytes.
        """
        raise NotImplementedError()

    def decode(self, data: bytes) -> tuple:
        """
        Decode the bytes to a tuple.
        """
        raise NotImplementedError()


class HttpMessageCodec(MessageCodec):
    """
    The HTML codec is able to convert raw bytes to a tuple containing:
    (HTTP Status Code, dict of Headers, Body).
    """

    def encode(self, data: tuple) -> bytes:
        """
        Encode HTTP data to bytes.
        """
        status = data[0]  # type: str
        headers = data[1]  # type: dict
        body = data[2]  # type: str

        separator = '\r\n'

        # is the body a dict?
        if isinstance(body, dict):
            body = urllib.parse.urlencode(body)

        headers['Content-Length'] = len(body)

        return (status + separator + separator.join(
            ['%s: %s' % (name, value) for name, value in headers.items()]) + separator + separator + body).encode()

    def decode(self, data: bytes) -> tuple:
        """
        Decode bytes to HTTP data.
        """
        payload = data.decode()

        msg = payload.split('\r\n\r\n', 1) if payload.find('\r\n\r\n') != -1 else (payload, '')
        headers = msg[0].split('\r\n')

        data_headers = {a[0]: a[1] for a in [[k.strip() for k in x.split(':')] for x in headers[1:] if len(x) > 0]}

        return headers[0], data_headers, msg[1]


class FrameMessageCodec(MessageCodec):
    """
    Frame messages are encoding according to RFC.
    """

    def encode(self, data: tuple) -> bytes:
        """
        Encode the frame data to bytes.
        """
        frame = []

        if data[0] == 'text':
            frame.append(129)
        elif data[0] == 'close':
            frame.append(136)
        elif data[0] == 'ping':
            frame.append(137)
        elif data[0] == 'pong':
            frame.append(138)

        payload_data = data[1].encode()
        size = len(payload_data)

        frame.append(self._yield_size_key(payload_data))

        if size > 65535:
            bin_size = '{0:064b}'.format(size)
            for i in range(0, 8):
                frame.append(int(bin_size[i * 8:i * 8 + 8], 2))
        elif size > 125:
            bin_size = '{0:016b}'.format(size)
            for i in range(0, 2):
                frame.append(int(bin_size[i * 8:i * 8 + 8], 2))

        frame.extend(self._yield_bytes(payload_data))

        return bytes(frame)

    def decode(self, data: bytes) -> tuple:
        """
        Decode bytes to the frame data.
        """
        code = int(('{0:08b}'.format(data[0]))[4:], 2)
        size = data[1] & 127

        if code == 1:
            message_type = 'text'
        elif code == 2:
            message_type = 'binary'
        elif code == 8:
            message_type = 'close'
        elif code == 9:
            message_type = 'ping'
        elif code == 10:
            message_type = 'pong'
        else:
            raise Exception('Unknown type for code "%d".' % data[0])

        if size == 127:
            message_length = int(''.join(['{0:08b}'.format(data[i + 2]) for i in range(0, 8)]), 2)
        elif size == 126:
            message_length = int('{0:08b}'.format(data[2]) + '{0:08b}'.format(data[3]), 2)
        else:
            message_length = size

        return message_type, ''.join(self._yield_chars(data[1:], message_length))

    def _yield_size_key(self, data) -> int:
        """
        Return the size key, depending on the size of the message this is
        either 127, 126 or the actual size.
        """
        size = len(data)

        if size > 65535:
            return 127
        elif size > 125:
            return 126

        return size

    def _yield_bytes(self, data) -> list:
        """
        Return the payload bytes.
        """
        return [data[i] for i in range(0, len(data))]

    def _yield_chars(self, data, length) -> list:
        """
        Return the converted characters.
        """
        size = data[0] & 127

        if size == 127:
            offset = 9
        elif size == 126:
            offset = 3
        else:
            offset = 1

        return [chr(data[i + offset]) for i in range(0, length)]


class MaskFactory:
    """
    Mask factory is able to generate a mask to use in the MaskedFrameMessageCoded.
    """

    def generate(self) -> list:
        raise NotImplementedError()


class DefaultMaskFactory(MaskFactory):
    """
    Mask factory which generates masks of four values according do the RFC.
    """

    def generate(self) -> list:
        return [random.randint(0, 255) for _ in range(0, 4)]


class MaskedFrameMessageCodec(FrameMessageCodec):
    """
    Masked messages are an additional security layer in the websocket protocol.
    It maskes the payload so it can not as easily be sniffed. Do not, this is
    not encryption, the message can be decoded regardless.
    """

    def __init__(self, factory: MaskFactory = None):
        self.mask_factory = DefaultMaskFactory() if factory is None else factory

    def _yield_size_key(self, data) -> int:
        """
        Return the size key, depending on the size of the message this is
        either 255, 254 or the actual size + 128.
        """
        return 128 + FrameMessageCodec._yield_size_key(self, data)

    def _yield_bytes(self, data) -> list:
        """
        Return the payload bytes.
        """
        mask = self.mask_factory.generate()
        masked_data = [(data[i] ^ mask[i % 4]) for i in range(0, len(data))]

        payload_data = []
        payload_data.extend(mask)
        payload_data.extend(masked_data)

        return payload_data

    def _yield_chars(self, data, length) -> list:
        """
        Return the converted characters.
        """
        size = data[0] & 127

        if size == 127:
            mask = [data[i] for i in range(9, 13)]
            offset = 13
        elif size == 126:
            mask = [data[i] for i in range(3, 7)]
            offset = 7
        else:
            mask = [data[i] for i in range(1, 5)]
            offset = 5

        return [chr(data[i + offset] ^ mask[i % 4]) for i in range(0, length)]


class SocketMessage:
    """
    Base class for the socket messages.

    See HttpMessage or FrameMessage.
    """

    def send(self, s: socket) -> None:
        """
        Send the message.
        """
        raise NotImplementedError()

    def message(self) -> str:
        """
        Return the message content.
        """
        raise NotImplementedError()


class HttpMessage(SocketMessage):
    """
    Basic HTTP message that can be send over the socket.
    """

    def __init__(self, message: tuple, codec: HttpMessageCodec = None):
        self.codec = HttpMessageCodec() if codec is None else codec
        self.data = message

    def message(self) -> str:
        """
        Return the message content.
        """
        return self.data[2]

    def status(self) -> int:
        """
        Return the HTTP status code.
        """
        status = self.data[0].split(' ')[1].strip()

        return int(status) if len(status) > 0 else 500

    def headers(self) -> dict:
        """
        Return all headers value.
        """
        return self.data[1]

    def header(self, key: str) -> str:
        """
        Return a header value.
        """
        return self.data[1][key]

    def send(self, s: socket) -> None:
        """
        Send the message.
        """
        s.send(self.codec.encode(self.data))


class FrameMessage(SocketMessage):
    """
    Frame message that can be send over the socket. These are the default messages.
    """

    def __init__(self, message: tuple, codec: FrameMessageCodec = None):
        self.codec = MaskedFrameMessageCodec() if codec is None else codec
        self.data = message

    def message(self) -> str:
        """
        Return the message content.
        """
        return self.data[1]

    def type(self) -> int:
        """
        Return the frame type.
        """
        return self.data[0]

    def send(self, s: socket) -> None:
        """
        Send the message.
        """
        s.send(self.codec.encode(self.data))


class SocketKey:
    """
    Socket keys can be used as a CSR token to make sure the received response
    belongs to a request.
    """

    def __init__(self):
        self._key = base64.b64encode(hashlib.sha1(str(random.getrandbits(1024)).encode('utf-8')).digest()).decode()

    def value(self) -> str:
        """
        Return the key value.
        """
        return self._key

    def valid(self, key: str) -> bool:
        """
        Validate the websocket return.
        """
        server_uuid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

        return key == base64.b64encode(hashlib.sha1((self._key + server_uuid).encode('utf-8')).digest()).decode()


class SocketFactory:
    """
    Socket factory which can create sockets.
    """

    def create(self):
        """
        Create a socket.
        """
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


class SslSocketFactory(SocketFactory):
    """
    Ssl socket factory which can create sockets which use a secure connection.
    """

    def create(self):
        """
        Create a socket.
        """
        return ssl.wrap_socket(SocketFactory.create(self))


class WebSocket:
    """
    Connection used to open en close the websocket connection. Call .send() or
    .read() to interact with the socket.
    """

    def __init__(self, host: str, socket_factory: SocketFactory = None):
        match = re.search('^([a-z]+)://([^/:]+)(:([0-9]+))?(/.*)$', host)
        port = 80

        if not match.group(1) in ['ws', 'wss']:
            raise ValueError('Websocket should start with ws:// or wss://')

        if not match.group(4) is None:
            port = int(match.group(4))
        elif match.group(1) == 'wss':
            port = 443

        self.host = match.group(2)
        self.port = port
        self.path = match.group(5)

        if socket_factory is None:
            socket_factory = SslSocketFactory() if self.port == 443 else SocketFactory()

        self._socket = socket_factory.create()

    def connect(self, handshake: bool = True) -> None:
        """
        Open connection to the websocket. This also does the handshake with the
        server if handshake is True, else this needs to be done separately by
        calling .handshake()
        """
        self._socket.connect((self.host, self.port))

        if handshake:
            self.handshake()

    def handshake(self, protocols: str = None) -> None:
        """
        Preform the handshake with the websocket.
        """
        key = SocketKey()
        codec = HttpMessageCodec()
        headers = {
            'Host': self.host,
            'Upgrade': 'websocket',
            'Origin': 'http://www.websocket.org',
            'Connection': 'Upgrade',
            'User-Agent': 'Mozilla 5.0',
            'Sec-WebSocket-Key': key.value(),
            'Sec-WebSocket-Version': '13',
            'Sec-WebSocket-Extensions': 'permessage-deflate; client_max_window_bits'
        }

        if protocols is not None:
            headers['Sec-WebSocket-Protocol'] = protocols

        self._send_message(HttpMessage(('GET %s HTTP/1.1' % self.path, headers, "Hello World!"), codec))

        msg = HttpMessage(codec.decode(self._read_message()), codec)

        if msg.status() != 200:
            self.close()
            raise Exception("Server responded with error %s, body: %s" % (msg.status(), msg.message()))

        if not key.valid(msg.header('Sec-WebSocket-Accept')):
            self.close()
            raise Exception("Response not valid")

    def close(self) -> None:
        """
        Close the connection to the websocket.
        """
        self._socket.close()

    def _send_message(self, message: SocketMessage) -> None:
        """
        Used internally to send a generic message of the socket.
        """
        message.send(self._socket)

    def _read_message(self) -> bytes:
        """
        Used internally to read generic data from the socket.
        """
        data = self._socket.recv(2048)

        if len(data) == 0:
            raise EOFError()

        return data

    def send(self, msg: str, message_type: str = 'text'):
        """
        Send a message over the socket.
        """
        self._send_message(FrameMessage((message_type, msg)))

    def receive(self) -> FrameMessage:
        """
        Read some data over the socket.
        """
        data = self._read_message()

        # check if the data is masked or not.
        masked = 1 == data[1] >> 7

        # pick the correct codec.
        codec = MaskedFrameMessageCodec() if masked else FrameMessageCodec()

        return FrameMessage(codec.decode(data), codec)
