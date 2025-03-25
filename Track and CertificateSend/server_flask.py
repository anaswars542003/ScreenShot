from flask import Flask, request, jsonify
import mysql.connector
from ecdsa.ellipticcurve import Point
from ecdsa.curves import  NIST256p
import struct
import hashlib
from server import create_cert
from flask import Flask, request, jsonify
import binascii

msk = int("29d8325cb77407dd3bd39158ce89f5c62e5d764e0aa64a6477973560abdaae47", 16)

app = Flask(__name__)

def get_oer_from_db(cid):
    """Fetch the OER from the database based on the given CID."""
    conn = mysql.connector.connect(
                                  user = 'TAServer', 
                                  password = '123456', 
                                  host = '127.0.0.1', 
                                  database = 'PRIVATE_ID'
                                )
    cursor = conn.cursor()
    cursor.execute("SELECT oer FROM certificates WHERE cid = %s", (cid,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

@app.route('/get_cert', methods=['POST'])
def get_oer():
    """API endpoint to fetch OER by CID."""
    data = request.get_json()
    if not data or 'cid' not in data:
        return jsonify({"error": "Missing CID"}), 400
    
    cid = data['cid']
    try:
        cid_bytes = bytes.fromhex(cid)  # Assuming CID is sent as a hex string
        if len(cid_bytes) != 32:
            return jsonify({"error": "Invalid CID length"}), 400
    except ValueError:
        return jsonify({"error": "Invalid CID format"}), 400
    
    oer = get_oer_from_db(cid_bytes)
    if oer is None:
        return jsonify({"error": "CID not found"}), 404
    
    return oer, 200, {'Content-Type': 'application/octet-stream'}




if __name__ == '__main__':
    app.run(debug=True)
