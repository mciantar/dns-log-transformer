from flask import Flask, request, jsonify, make_response
import logging
import base64
import time
import jsonschema
import json
import os
import logging.handlers
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
executor = ThreadPoolExecutor(2)  # Adjust the number of threads as needed

logging.basicConfig(level=logging.INFO)

# Schema definition based on the provided YAML
request_schema = {
    "type": "object",
    "properties": {
        "requestId": {"type": "string"},
        "timestamp": {"type": "integer"},
        "records": {
            "type": "array",
            "minItems": 1,
            "maxItems": 10000,
            "items": {
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "minLength": 0,
                        "maxLength": 1365336
                    }
                },
                "required": ["data"]
            }
        }
    },
    "required": ["requestId", "records"]
}

@app.route('/endpoint', methods=['POST'])
def kinesis_endpoint():
    current_timestamp = int(time.time() * 1000)  # Current time in ms since epoch

    # Validate request method
    if request.method != 'POST':
        return jsonify({'error': 'Invalid request method'}), 405

    # Validate content type
    if request.content_type != 'application/json':
        return jsonify({
            'requestId': 'unknown',
            'timestamp': current_timestamp,
            'errorMessage': 'Invalid content type. Expected application/json.'
        }), 400

    # Extract and validate request data
    try:
        data = request.get_json()
        validate_data(data)
        request_id = data['requestId']
        records = data['records']
    except KeyError as e:
        return jsonify({
            'requestId': 'unknown',
            'timestamp': current_timestamp,
            'errorMessage': f'Missing key in request: {str(e)}'
        }), 400
    except jsonschema.exceptions.ValidationError as e:
        return jsonify({
            'requestId': 'unknown',
            'timestamp': current_timestamp,
            'errorMessage': f'Invalid data format: {str(e)}'
        }), 400

    # Process data in a separate thread
    executor.submit(process_data, records)

    # Respond with success
    return jsonify({
        'requestId': request_id,
        'timestamp': current_timestamp
    }), 200

def validate_data(data):
    jsonschema.validate(instance=data, schema=request_schema)

class DNSQuery:
    def __init__(self, version, account_id, region, vpc_id, query_timestamp,
                 query_name, query_type, query_class, rcode, answers,
                 srcaddr, srcport, transport, srcids):
        self.version = version
        self.account_id = account_id
        self.region = region
        self.vpc_id = vpc_id
        self.query_timestamp = query_timestamp
        self.query_name = query_name
        self.query_type = query_type
        self.query_class = query_class
        self.rcode = rcode
        self.answers = answers
        self.srcaddr = srcaddr
        self.srcport = srcport
        self.transport = transport
        self.srcids = srcids

    def to_microsoft_dns_log_format(self):
        # Convert the timestamp to the desired format
        # Assuming the timestamp in the JSON data is in ISO 8601 format
        from datetime import datetime
        dt = datetime.strptime(self.query_timestamp, "%Y-%m-%dT%H:%M:%SZ")
        formatted_timestamp = dt.strftime("%d/%m/%Y %H:%M:%S")

        # Extract the first answer's type if available, otherwise use a placeholder
        answer_type = self.answers[0]['Type'] if self.answers else "A"

        # Construct the domain name section
        # Note: This is a simplified version and might need to be adjusted based on your exact requirements
        domain_name_section = f"({len(self.query_name)}){self.query_name}(0)"

        # Construct the log entry
        log_entry = f"{formatted_timestamp} 0D2C PACKET  0000000001ED00C0 {self.transport} Snd {self.srcaddr} " \
                    f"{self.srcport} R Q [{self.rcode} A DR {self.rcode}] {answer_type} {domain_name_section}"

        return log_entry

    def to_bind9_log_format(self):
        # Convert the timestamp to the desired format
        from datetime import datetime
        dt = datetime.strptime(self.query_timestamp, "%Y-%m-%dT%H:%M:%SZ")
        syslog_timestamp = dt.strftime("%b %d %H:%M:%S")
        bind9_timestamp = dt.strftime("%d-%b-%Y %H:%M:%S.000")

        # Extract the first answer's type if available, otherwise use a placeholder
        query_type = self.answers[0]['Type'] if self.answers else "A"

        # Construct the query log entry
        query_log_entry = f"{syslog_timestamp} {self.vpc_id} route53resolver: {bind9_timestamp} client " \
                          f"{self.srcaddr}#{self.srcport}: query: {self.query_name} IN {query_type} + (127.0.0.1)"

        log_entries = [query_log_entry]

        # Construct reply log entries for each answer if answers are present
        if self.answers:
            for answer in self.answers:
                rdata = answer.get('Rdata', 'N/A')
                reply_log_entry = f"{syslog_timestamp} {self.vpc_id} route53resolver: {bind9_timestamp} client " \
                                  f"{self.srcaddr}#{self.srcport}: reply: {self.query_name} is {rdata}"
                log_entries.append(reply_log_entry)

        return "\n".join(log_entries)

def setup_syslog_logging():
    syslog_server = '172.31.1.18'
    syslog_port = 514  # Default syslog UDP port

    # Set up the SysLogHandler without a formatter
    syslog_handler = logging.handlers.SysLogHandler(address=(syslog_server, syslog_port),
                                                    facility=logging.handlers.SysLogHandler.LOG_SYSLOG)

    # Add the handler to your logger
    logger = logging.getLogger()
    logger.addHandler(syslog_handler)
    logger.setLevel(logging.DEBUG)

    return logger

def process_data(records):
    for record in records:
        try:
            decoded_data = base64.b64decode(record['data']).decode('utf-8')
            # logging.info(f"Decoded data: {decoded_data}")

            # Parse the JSON data
            dns_data = json.loads(decoded_data)

            # Create a DNSQuery object
            dns_query = DNSQuery(
                version=dns_data['version'],
                account_id=dns_data['account_id'],
                region=dns_data['region'],
                vpc_id=dns_data['vpc_id'],
                query_timestamp=dns_data['query_timestamp'],
                query_name=dns_data['query_name'],
                query_type=dns_data['query_type'],
                query_class=dns_data['query_class'],
                rcode=dns_data['rcode'],
                answers=dns_data['answers'],
                srcaddr=dns_data['srcaddr'],
                srcport=dns_data['srcport'],
                transport=dns_data['transport'],
                srcids=dns_data['srcids']
            )

            logger = setup_syslog_logging()
            log_entries = dns_query.to_bind9_log_format().split('\n')
            for entry in log_entries:
                logger.info(entry)

            # Log the data in the Bind9 DNS log format
            # logging.info(dns_query.to_bind9_log_format())

        except Exception as e:
            logging.error(f"Error processing data: {str(e)}")


@app.route("/health", methods=["GET"])
def health():
    return make_response("", 200)

@app.errorhandler(400)
def bad_request_error(error):
    return jsonify(error="Bad Request"), 400

@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"Internal Server Error: {str(error)}")
    return jsonify(error="Internal Server Error"), 500

#if __name__ == '__main__':
app.run(threaded=True, host="0.0.0.0", port=int(os.getenv("SERVICE_PORT")))
#    app.run(threaded=True, host="0.0.0.0", port=5000)
