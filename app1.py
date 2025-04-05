from flask import Flask, request, jsonify
from function1 import ask_openai

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    return "RINGEXPERT Flask backend is running!"

@app.route('/ask', methods=['POST'])
def ask():
    try:
        data = request.get_json()
        question = data.get("question")
        if not question:
            return jsonify({"error": "No question provided"}), 400

        answer = ask_openai(question)
        return jsonify({"answer": answer})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
