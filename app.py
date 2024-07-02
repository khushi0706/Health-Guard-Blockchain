from flask import Flask, request, render_template, jsonify, session, redirect, url_for
from web3 import Web3
import json
import os
import time
import logging
from sphincs_wrapper import generate_keypair as generate_sphincs_keypair, sign_message as sign_message_sphincs, verify_signature as verify_signature_sphincs
from dilithium_wrapper import generate_keypair as generate_dilithium_keypair, sign_message as sign_message_dilithium, verify_signature as verify_signature_dilithium

app = Flask(__name__)
app.secret_key = os.urandom(24)  


logging.basicConfig(level=logging.DEBUG)


ganache_url = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(ganache_url))

try:
    with open('build/contracts/Healthcare.json') as f:
        contract_info = json.load(f)
        contract_address = contract_info['networks']['5777']['address']
        contract_abi = contract_info['abi']
        logging.info("Contract ABI and address loaded successfully.")
except Exception as e:
    logging.error(f"Error loading contract JSON file: {e}")
    contract_address = None
    contract_abi = None

if contract_address and contract_abi:
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
else:
    contract = None
    logging.error("Contract not initialized properly. Check if contract ABI and address are loaded correctly.")


def measure_performance(function, *args, repetitions=10):
    total_time = 0

    for _ in range(repetitions):
        start_time = time.time()
        function(*args)
        end_time = time.time()
        
        execution_time = (end_time - start_time) * 1000000  
        total_time += execution_time
    
    avg_time = total_time / repetitions
    
    avg_time_formatted = f"{avg_time:.3f}"

    return avg_time_formatted
	



def generate_sphincs_keypair_with_metrics():
    avg_time = measure_performance(generate_sphincs_keypair)
    return generate_sphincs_keypair(), avg_time


def sign_message_sphincs_with_metrics(message, sk):
    avg_time = measure_performance(sign_message_sphincs, message, sk)
    return sign_message_sphincs(message, sk), avg_time


def verify_signature_sphincs_with_metrics(signature, pk):
    avg_time = measure_performance(verify_signature_sphincs, signature, pk)
    return verify_signature_sphincs(signature, pk), avg_time


def generate_dilithium_keypair_with_metrics():
    avg_time = measure_performance(generate_dilithium_keypair)
    return generate_dilithium_keypair(), avg_time


def sign_message_dilithium_with_metrics(message, sk):
    avg_time = measure_performance(sign_message_dilithium, message, sk)
    return sign_message_dilithium(message, sk), avg_time


def verify_signature_dilithium_with_metrics(message,signature, pk):
    avg_time = measure_performance(verify_signature_dilithium, message, signature, pk)
    return verify_signature_dilithium(message, signature, pk), avg_time

@app.route('/store_patient_details', methods=['POST'])
def store_patient_details():
    try:
        patient_details = request.json

        if not patient_details:
            logging.error("No patient details received.")
            return jsonify({'error': 'No patient details received'}), 400

        session['patient_details'] = patient_details
        logging.debug(f"Stored patient details in session: {session['patient_details']}")
        
        return jsonify({'message': 'Patient details stored in session successfully'}), 200
    except Exception as e:
        logging.error(f"Error in /store_patient_details route: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/')
def index():
    return render_template('index.html', contract_abi=contract_abi, contract_address=contract_address)

@app.route('/submit', methods=['POST'])
def submit():
    if not contract:
        logging.error("Contract not loaded properly.")
        return jsonify({'error': 'Contract not loaded properly'}), 500

    try:
        patient_name = request.form['patient_name']
        patient_age = request.form['patient_age']
        patient_gender = request.form['patient_gender']
        patient_condition = request.form['patient_condition']
        patient_contact = request.form['patient_contact']
        patient_history = request.form['patient_history']

        #session.clear()  
        session['patient_details'] = {
            'name': patient_name,
            'age': patient_age,
            'gender': patient_gender,
            'condition': patient_condition,
            'contact': patient_contact,
            'history': patient_history
        }

        logging.debug(f"Session patient details: {session['patient_details']}")

       
        contract.functions.addPatient(patient_name, int(patient_age), patient_gender, patient_condition, patient_contact, patient_history).transact({'from': web3.eth.defaultAccount})

        return redirect(url_for('result'))
    except Exception as e:
        logging.error(f"Error in /submit route: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/result')
def result():
    try:
        patient_details = session.get('patient_details')

        if not patient_details:
            logging.error("No patient details found in session.")
            return jsonify({'error': 'No patient details found in session'}), 500

        logging.debug(f"Retrieved patient details from session: {patient_details}")

        patient_message = json.dumps(patient_details).encode('utf-8')

        # Generate SPHINCS+ keypair 
        (sphincs_public_key, sphincs_secret_key), sphincs_keypair_gen_time = generate_sphincs_keypair_with_metrics()

        # Sign the message with SPHINCS+ and measure performance
        sphincs_signature, sphincs_signing_time = sign_message_sphincs_with_metrics(patient_message, sphincs_secret_key)

        # Verify the SPHINCS+ signature and measure performance
        sphincs_verification_result = None
        sphincs_verification_time = 0
        if sphincs_signature and sphincs_public_key:  
            try:
                sphincs_is_valid, sphincs_verification_time = verify_signature_sphincs_with_metrics(sphincs_signature, sphincs_public_key)
                sphincs_verification_result = "SIGNATURE IS VALID" if sphincs_is_valid else "SIGNATURE IS INVALID"
            except Exception as e:
                sphincs_verification_result = f"Error verifying SPHINCS+ signature: {str(e)}"
        
        # Generate Dilithium keypair 
        (dilithium_public_key, dilithium_secret_key), dilithium_keypair_gen_time = generate_dilithium_keypair_with_metrics()

        # Sign the message with Dilithium and measure performance
        dilithium_signature, dilithium_signing_time = sign_message_dilithium_with_metrics(patient_message, dilithium_secret_key)

        # Verify the Dilithium signature and measure performance
        dilithium_verification_result = None
        dilithium_verification_time = 0
        if dilithium_signature and dilithium_public_key:  
            try:
                dilithium_is_valid, dilithium_verification_time = verify_signature_dilithium_with_metrics(patient_message, dilithium_signature, dilithium_public_key)
                dilithium_verification_result = "SIGNATURE IS VALID" if dilithium_is_valid else "SIGNATURE IS INVALID"
            except Exception as e:
                dilithium_verification_result = f"Error verifying Dilithium signature: {str(e)}"

        # Sizes in kilobytes
        sphincs_signature_size_kb = f"{len(sphincs_signature) / 1024.0:.3f}" if sphincs_signature else None
        sphincs_public_key_size_kb = f"{len(sphincs_public_key) / 1024.0:.3f}" if sphincs_public_key else None
        sphincs_secret_key_size_kb = f"{len(sphincs_secret_key) / 1024.0:.3f}" if sphincs_secret_key else None

        dilithium_signature_size_kb = f"{len(dilithium_signature) / 1024.0:.3f}" if dilithium_signature else None
        dilithium_public_key_size_kb = f"{len(dilithium_public_key) / 1024.0:.3f}" if dilithium_public_key else None
        dilithium_secret_key_size_kb = f"{len(dilithium_secret_key) / 1024.0:.3f}" if dilithium_secret_key else None

	

        # response data
        response = {
            'patient_details': patient_details,
            'message': patient_message.decode('utf-8'),
            'sphincs_signature': sphincs_signature.hex() if sphincs_signature else None,
            'sphincs_verification_result': sphincs_verification_result,
            'sphincs_keypair_generation_time': sphincs_keypair_gen_time,
            'sphincs_signing_time': sphincs_signing_time,
            'sphincs_verification_time': sphincs_verification_time,
            'sphincs_signature_size_kb': sphincs_signature_size_kb,
            'sphincs_public_key_size_kb': sphincs_public_key_size_kb,
            'sphincs_secret_key_size_kb': sphincs_secret_key_size_kb,
            'sphincs_public_key': sphincs_public_key.hex() if sphincs_public_key else None,
            'sphincs_secret_key': sphincs_secret_key.hex() if sphincs_secret_key else None,

            'dilithium_signature': dilithium_signature.hex() if dilithium_signature else None,
            'dilithium_verification_result': dilithium_verification_result,
            'dilithium_keypair_generation_time': dilithium_keypair_gen_time,
            'dilithium_signing_time': dilithium_signing_time,
            'dilithium_verification_time': dilithium_verification_time,
            'dilithium_signature_size_kb': dilithium_signature_size_kb,
            'dilithium_public_key_size_kb': dilithium_public_key_size_kb,
            'dilithium_secret_key_size_kb': dilithium_secret_key_size_kb,
            'dilithium_public_key': dilithium_public_key.hex() if dilithium_public_key else None,
            'dilithium_secret_key': dilithium_secret_key.hex() if dilithium_secret_key else None
        }

        return render_template('result.html', **response)

    except Exception as e:
        logging.error(f"Error in /result route: {e}")
        return jsonify({'error': str(e)}), 500

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
    

