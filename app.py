from flask import Flask, render_template, jsonify, request
import main

app = Flask(__name__)


# Route to render the index.html template
@app.route('/')
def index():
    return render_template('index.html')


# Route to handle the AJAX request for getting WiFi name
@app.route('/get_wifi_name')
def get_wifi_name():
    wifi_name = main.get_wifi_name()
    return jsonify(wifi_name=wifi_name)

# Route to handle the AJAX request for getting WiFi signal
@app.route('/get_wifi_signal_strength')
def get_wifi_signal_strength():
    wifi_strength = main.get_wifi_signal_strength()
    return jsonify(wifi_strength=wifi_strength)

# Route to handle the AJAX request for getting Isolation Score
@app.route('/check_guest_network_isolation')
def check_guest_network_isolation():
    isolation_score = main.check_guest_network_isolation()
    return jsonify(isolation_score=isolation_score)

# Route to handle the AJAX request for getting protocol Score
@app.route('/get_security_score')
def get_security_score():
    protocol_score = main.get_security_score()
    return jsonify(protocol_score=protocol_score)

# Route to handle the AJAX request for getting firewall Score
@app.route('/get_firewall_score')
def get_firewall_score():
    firewall_score = main.get_firewall_score()
    return jsonify(firewall_score=firewall_score)


@app.route('/get_password_score', methods=['POST'])
def calculate_password_score():
    # Get the password from the request data
    password = request.json.get('password')

    # Calculate the password score
    password_score = main.get_password_score(password)

    # Return the password score as JSON response
    return jsonify({'password_score': password_score})

if __name__ == '__main__':
    app.run(debug=True)
