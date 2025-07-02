from flask import Flask, request, jsonify, render_template
from flask import Flask, request, jsonify
from ml_model import predict_packet

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()

    if "packet_size" not in data:
        return jsonify({"error": "Missing 'packet_size' in request"}), 400

    try:
        size = int(data["packet_size"])
        label = predict_packet(size)
        return jsonify({"packet_size": size, "prediction": label})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
