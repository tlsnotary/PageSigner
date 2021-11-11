import socket, threading, json, base64, time, datetime
connections = {} #uid:{buffer:, socketId:} 
httpRespStr = 'HTTP/1.0 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n'

def handler(sock):
    raw = sock.recv(10000)
    payload = raw.decode().split('\r\n\r\n')[1]
    if len(payload) == 0:  #Maybe HTTP POST body arrived late. Trying again
        raw += sock.recv(10000)
        payload = raw.decode().split('\r\n\r\n')[1]
    j = json.loads(payload)

    if j['command'] == 'connect':
        if j['args']['port'] == -1:
            sock.send((httpRespStr + json.dumps({'retval':'active'})).encode())
            sock.close()
            return
        clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientSock.settimeout(None)
        clientSock.connect((j['args']['name'], j['args']['port']))
        print( datetime.datetime.now().strftime("%H:%M:%S"), ' connected to ',j['args']['name'])
        connections[j['uid']] = {'buffer':b'', 'socket': clientSock}
        sock.send((httpRespStr + json.dumps({'retval':'success'})).encode())
        sock.close()
        while True:
            data = clientSock.recv(1000000)
            if len(data) == 0:
                break #the blocking socket returns 0 when it was closed
            connections[j['uid']]['buffer'] += data

    if j['command'] == 'send':
        clientSock = connections[j['uid']]['socket']
        clientSock.send(base64.b64decode(j['args']['data']))
        #if we don't send a response back then there will be an error on the console
        sock.send((httpRespStr).encode())
        sock.close()

    if j['command'] == 'close':
        connections[j['uid']]['socket'].close()
        del connections[j['uid']]
        sock.send((httpRespStr).encode())
        sock.close()

    if j['command'] == 'recv':
        tmp = connections[j['uid']]['buffer']
        connections[j['uid']]['buffer'] = b''
        sock.send((httpRespStr + json.dumps({'data':base64.b64encode(tmp).decode()})).encode())
        sock.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 20022))
sock.listen(100) #as many as possible
print("PageSigner helper app is running. You can now perform notarizations in your browser. This window must remain open.")
while True:
    try:
        connection, client_address = sock.accept()
        threading.Thread(target=handler, args=(connection,)).start()
    except Exception as e:
        print('Exception caught', e)