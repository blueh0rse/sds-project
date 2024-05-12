from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    # Return the home page and all the routes of the API as a html page
    return '''
    <h1>Simple API</h1>
    <p>A prototype API for distant reading of science fiction novels.</p>
    <p>Available routes:</p>
    <ul>
        <a href="/about">About</a>
        <a href="/contact">Contact</a>
    </ul>
    '''

@app.route('/about')
def about():
    return 'This is the about page.'

@app.route('/contact')
def contact():
    return 'You can contact us at contact@example.com.'

@app.route('/hidden-route')
def hidden():
    return 'This is a honeypot route.'

if __name__ == '__main__':
    app.run(port=80)