import socket
import hashlib
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1, NIST256p
from ecdsa import SigningKey
import redis
import mysql.connector
import struct
import time
import asn1tools
from ecdsa.util import sigdecode_string

HOST = '127.0.0.1'
PORT = 12346
msk = int("29d8325cb77407dd3bd39158ce89f5c62e5d764e0aa64a6477973560abdaae47", 16)


def create_cert(c1_c2,  cid):
    r = redis.Redis(host='localhost', port=6379, db=0)
    r.set(cid, c1_c2)
    
    asn1_schema = asn1tools.compile_files("ASN/CertificateBase.asn1","oer")

    to_be_signed_data = {
        "id" :  cid,
        "validity" : {"end" : int(time.time()) +7200 },
        "anonymousPK" : c1_c2
    }
    encoded_tobe_signed = asn1_schema.encode('ToBeSignedCertificate', to_be_signed_data)

    hash_digest = hashlib.sha256(encoded_tobe_signed).digest()
    private_key = SigningKey.from_secret_exponent(msk, curve=NIST256p)
    public_key = private_key.get_verifying_key()

    signature = private_key.sign_digest_deterministic(hash_digest)
    r, s = sigdecode_string(signature, NIST256p.order)

    signature_data = (
        "ecdsaNistP256Signature", 
        {
            "rSig": {
                "x": r.to_bytes(32, byteorder='big')
                
            },
            "sSig": s.to_bytes(32, byteorder='big')
        }
    )

    certificate_data = {
        "version": 3,
        "tobeSignedData": to_be_signed_data,
        "signature": signature_data
    }

    encoded_certificate = asn1_schema.encode('CertificateBase', certificate_data)
    

    cnx = mysql.connector.connect(user = 'TAServer', 
                                  password = '123456', 
                                  host = '127.0.0.1', 
                                  database = 'PRIVATE_ID')
    
    cursor = cnx.cursor()
    #encoded_certificate oer( BLOB )
    #cid   cid
    expiry_time = int(time.time()) + 7200  # 2 hours from now (UNIX timestamp)
    current_time = int(time.time())

    # Convert expiry_time to MySQL TIMESTAMP format
    expiry_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(expiry_time))
    cur_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(current_time))

    sql = "INSERT INTO certificates (cid, oer, expiry_time, created_at) VALUES (%s, %s, %s, %s)"
    values = (cid, encoded_certificate, expiry_timestamp, cur_timestamp)
    cursor.execute(sql, values)
    cnx.commit()
    cnx.close()
    

def publish_apkey(c1, c2, client_socket):
    c1_x = c1.x().to_bytes(32, byteorder = 'big')
    c1_y = c1.y().to_bytes(32, byteorder = 'big')
    c2_x = c2.x().to_bytes(32, byteorder = 'big')
    c2_y = c2.y().to_bytes(32, byteorder = 'big')

    c1_c2 = c1_x + c1_y + c2_x + c2_y

    cid = hashlib.sha256(c1_c2).digest()
    print("hash: "+cid.hex())

    create_cert(c1_c2, cid)
    client_socket.sendall(cid)
    client_socket.sendall(c1_c2)

    return cid
    


def private_store(c1,c3, cid, pk_bytes, user_id):
    c1_x = c1.x().to_bytes(32, byteorder = 'big')
    c1_y = c1.y().to_bytes(32, byteorder = 'big')
    c3_x = c3.x().to_bytes(32, byteorder = 'big')
    c3_y = c3.y().to_bytes(32, byteorder = 'big')
    
    cnx = mysql.connector.connect(user = 'TAServer', 
                                  password = '123456', 
                                  host = '127.0.0.1', 
                                  database = 'PRIVATE_ID')
    cursor = cnx.cursor()

    insert_query = ("INSERT INTO cid_store" 
                    "(cid, c1_x, c1_y, c3_x, c3_y, current_i)"
                    "VALUES (%(cid)s, %(c1_x)s, %(c1_y)s, %(c3_x)s, %(c3_y)s, %(current_i)s)")
    
    data_cid = {
        'cid': cid,
        'c1_x': c1_x,
        'c1_y': c1_y,
        'c3_x': c3_x,
        'c3_y': c3_y,
        'current_i': 1
    }
    cursor.execute(insert_query, data_cid)
    cnx.commit()
    cursor.close()
    
    
    cursor = cnx.cursor()
    
    insert_query2 = ("INSERT INTO pk_id"
    			"(pk, id_user)"
    			"VALUES (%(pk_bytes)s, %(user_id)s)")
    			
    data_pk_id = {
	'pk_bytes' : pk_bytes,
	'user_id' : user_id,
    }
    cursor.execute(insert_query2, data_pk_id)
    cnx.commit()
    cursor.close()

    cnx.close()




def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('socket created')
    server_socket.bind((HOST, PORT))
    print('socket binded')
    server_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")
    
    try:
        while True:
            client_socket, client_adddress = server_socket.accept()
            print(f"Connection established with {client_adddress}")
            data = client_socket.recv(64)
            if len(data) != 64:
                print(f"Invalid data length: {len(data)} bytes received")
                client_socket.close()
                continue
            x_bytes = data[:32]
            y_bytes = data[32:]
            x = int.from_bytes(x_bytes, byteorder='big')
            y = int.from_bytes(y_bytes, byteorder='big')

            curve = NIST256p.curve
            pk = Point(curve, x, y)
            mpk = msk * NIST256p.generator
            print(f"Public key recieved \npk_x:{hex(pk.x())}\npk_y:{hex(pk.y())}")
            
            print('user id: ')
            user_id = input()
            
            pk_bytes = x_bytes + y_bytes
            byte_representation = struct.pack('I', 1)
            pk_bytes += byte_representation
            hash_result = hashlib.sha256(pk_bytes).hexdigest()
            u = int(hash_result, 16)


            
            c1 = u * NIST256p.generator
            c2 = (u + 1) * pk
            c3 = u * mpk + pk
            print(f"\nc1_x:{hex(c1.x())}\nc1_y:{hex(c1.y())}")
            print(f"\nc2_x:{hex(c2.x())}\nc2_y:{hex(c2.y())}")
            print(f"\nc3_x:{hex(c3.x())}\nc3_y:{hex(c3.y())}\n\n")
            
            cid = publish_apkey(c1, c2, client_socket)
            private_store(c1, c3, cid, data, user_id)
            


    except KeyboardInterrupt:
        print("server shutting down")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
