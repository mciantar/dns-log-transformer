# DNS Log Transformer
Rapid7 Insight IDR lacks the ability to digest and parse AWS Route53 Resolver Logs. A workaround to this would be to tranform these logs into a format which Rapid7 IDR Supports and Understands. This application is an attempt to do exactly this.

# Credits
This is a Flask application and for quick deployment we are using the code from Mohame Kari from this project: https://github.com/MohamedKari/secure-flask-container-template. The files changed are the following:
requirements.txt
docker-compose.yml
app/app.py
