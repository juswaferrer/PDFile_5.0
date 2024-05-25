@app.route('/forgotpass', methods=['GET', 'POST'])
def forgot_password():
    return render_template('forgotpass.html')