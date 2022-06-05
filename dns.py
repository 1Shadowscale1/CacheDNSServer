import datetime
import glob
import json
import socket


def get_bit_in_byte(byte, position):
    return str(ord(byte) & (1 << position))


def save_data_info(data):
    with open(f'infos/{data["origin"]}.info', 'w+') as file:
        json.dump(data, file)


def build_request(domain, qtype):
    return b'\xAA\xAA' + b'\x01\x00' + b'\x00\x01' + (0).to_bytes(2, byteorder='big') + \
           (0).to_bytes(2, byteorder='big') + (0).to_bytes(2, byteorder='big') + do_question(domain, qtype)


def parse_header(data):
    return {'ID': data[0:2], 'FLAGS': parse_flags(data[2:4]), 'QDCOUNT': int.from_bytes(data[4:6], 'big'),
            'ANCOUNT': int.from_bytes(data[6:8], 'big'), 'NSCOUNT': int.from_bytes(data[8:10], 'big'),
            'ARCOUNT': int.from_bytes(data[10:12], 'big')}


def parse_incoming_request(data):
    d_parts, qtype = get_user_request(data[12:])
    return {'header': parse_header(data),
            'question': {'QNAME': '.'.join(d_parts), 'QTYPE': make_type_from_number(int.from_bytes(qtype, 'big')),
                         'QCLASS': 'internet'}}


def do_ipv4_bytes(data):
    ip = ''
    for b in data:
        ip += str(b) + '.'
    return ip.rstrip('.')


def do_flags_into_bytes(*args):
    st = ''
    for a in args:
        st += a
    return int(st, 2).to_bytes(1, byteorder='big')


def make_type_from_number(type):
    if type == 2:
        return 'ns'
    if type == 1:
        return 'a'


def build_response_flags(flags):
    first_byte = flags[:1]
    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += str(ord(first_byte) & (1 << bit))
    return do_flags_into_bytes('1' + OPCODE + '101') + do_flags_into_bytes('10000000')


def info_from_dns_response(data, domain, qtype):
    recs = get_records_from_answer(data[12 + len(do_question(domain, qtype)):], int.from_bytes(data[6:8], 'big'))
    new_entry = {'origin': '.'.join(domain), 'time': str(datetime.datetime.now()), 'data': recs, 'ttl': 360}
    CACHE['.'.join(domain)] = new_entry
    save_data_info(new_entry)
    return new_entry


def build_response(data):
    rdata = get_records_domain(data[12:])
    body = b''
    records, rec_type, domain = rdata
    for record in records:
        body += record_to_bytes(rec_type, record['ttl'], record['value'])
    print(f'Answer on request - type "{rec_type}" through "{".".join(domain)}" sent.')
    return data[0:2] + build_response_flags(data[2:4]) + b'\x00\x01' + len(rdata[0]).to_bytes(2, byteorder='big') + \
           (0).to_bytes(2, byteorder='big') + (0).to_bytes(2, byteorder='big') + do_question(domain, rec_type) + body


def do_question(domain, qtype):
    q = b''
    for part in domain:
        q += bytes([len(part)])
        for char in part:
            q += ord(char).to_bytes(1, byteorder='big')
    if qtype == 'ns':
        q += (2).to_bytes(2, byteorder='big')
    if qtype == 'a':
        q += (1).to_bytes(2, byteorder='big')
    q += (1).to_bytes(2, byteorder='big')
    return q


def load_cache():
    json_inf = {}
    inf_files = glob.glob('infos/*.info')
    print('Cache loading.')
    for z in inf_files:
        with open(z) as file:
            d = json.load(file)
            json_inf[d['origin']] = d
    print(f'Cache loading ended. Loaded {len(json_inf)} objects.')
    return json_inf


def ask_new_data(domain, qtype):
    req = build_request(domain, qtype)
    tsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        tsock.sendto(req, GOOGLE_NS)
        data, _ = tsock.recvfrom(512)
    finally:
        tsock.close()
    return info_from_dns_response(data, domain, qtype)


def do_response(data):
    request_info = parse_incoming_request(data)
    resp = b''
    req_type = request_info['question']['QTYPE']
    if req_type == 'a' or req_type == 'ns':
        print(f'Got request of type "{req_type}". Allow request...')
        resp = build_response(data)
    return resp


def get_records_domain(data):
    d, qtype = get_user_request(data)
    QT = ''
    if qtype == b'\x00\x01':
        QT = 'a'
    if qtype == (12).to_bytes(2, byteorder='big'):
        QT = 'ptr'
    if qtype == (2).to_bytes(2, byteorder='big'):
        QT = 'ns'
    recs = None
    if QT == 'a' or QT == 'ns':
        info = get_data_domain(d, CACHE, QT)
        recs = info['data'][QT]
    return recs, QT, d


def get_data_domain(domain, cache, qtype):
    d_name = '.'.join(domain)
    if d_name not in cache:
        print(f'No data in cache about "{d_name}". Requesting root DNS server.')
        return ask_new_data(domain, qtype)
    else:
        print(f'Data {d_name} found in cache.')
        d_cache = cache[d_name]
        if qtype not in d_cache['data']:
            print(f'Data about "{qtype}" request not found. Requesting root DNS server.')
            return ask_new_data(domain, qtype)
        else:
            time = datetime.datetime.fromisoformat(d_cache['time'])
            ttl = d_cache['ttl']
            current_time = datetime.datetime.now()
            if (current_time - time).seconds > ttl:
                print(f'Data "{d_name}" got old. Requesting root DNS server.')
                return ask_new_data(domain, qtype)
    return d_cache


def get_records_from_answer(answer, count):
    ptr = 0
    recs = {}
    for _ in range(count):
        rec = {}
        rtype = int.from_bytes(answer[ptr + 2: ptr + 4], 'big')
        rdlen = int.from_bytes(answer[ptr + 10: ptr + 12], 'big')
        rddata = ''
        if rtype == 1:
            rddata = do_ipv4_bytes(answer[ptr + 12:ptr + 12 + rdlen])
        if rtype == 2:
            rddata = answer[ptr + 12:ptr + 12 + rdlen].hex()
        ptr += 12 + rdlen
        rtype = make_type_from_number(rtype)
        rec['ttl'] = int.from_bytes(answer[ptr + 6:ptr + 10], 'big')
        rec['value'] = rddata
        if rtype not in recs:
            recs[rtype] = [rec]
        else:
            recs[rtype].append(rec)
    return recs


def parse_flags(flags):
    fbyte = flags[:1]
    sbyte = flags[1:2]
    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += get_bit_in_byte(fbyte, bit)
    RCODE = ''
    for bit in range(4, 8):
        RCODE += get_bit_in_byte(fbyte, bit)
    return {'QR': get_bit_in_byte(fbyte, 0), 'OPCODE': OPCODE, 'AA': get_bit_in_byte(fbyte, 5),
            'TC': get_bit_in_byte(fbyte, 6), 'RD': get_bit_in_byte(fbyte, 7), 'RA': get_bit_in_byte(sbyte, 8),
            'Z': '0000', 'RCODE': RCODE}


def get_user_request(data):
    state, exp_len, x, y = 0, 0, 0, 0
    dstr, dparts = '', []
    for byte in data:
        if state != 1:
            state, exp_len = 1, byte
        else:
            if byte != 0:
                dstr += chr(byte)
            x += 1
            if byte == 0:
                dparts.append(dstr)
                break
            if x == exp_len:
                dparts.append(dstr)
                dstr, state, x = '', 0, 0
        y += 1
    question_type = data[y: y + 2]
    return dparts, question_type


def record_to_bytes(rec_type, ttl, value):
    record = b'\xc0\x0c'
    if rec_type == 'ns':
        record += bytes([0]) + bytes([2])
    if rec_type == 'a':
        record += bytes([0]) + bytes([1])
    record += bytes([0]) + bytes([1])
    record += int(ttl).to_bytes(4, byteorder='big')
    if rec_type == 'a':
        record += bytes([0]) + bytes([4])
        for part in value.split('.'):
            record += bytes([int(part)])
    if rec_type == 'ns':
        byte_value = bytes(bytearray.fromhex(value))
        record += bytes([0]) + bytes([len(byte_value)])
        record += byte_value
    return record


CACHE = load_cache()
GOOGLE_NS = '8.8.8.8', 53

if __name__ == "__main__":

    ip = '127.0.0.1'
    port = 53
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print('Working')
    while True:
        data, addr = sock.recvfrom(512)
        response = do_response(data)
        sock.sendto(response, addr)
