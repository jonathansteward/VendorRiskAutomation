from app import app

if __name__ == "__main__":
    print("Starting Vendor Risk Assessment Platform at http://127.0.0.1:5000")
    app.run(debug=False, threaded=True, port=5000)