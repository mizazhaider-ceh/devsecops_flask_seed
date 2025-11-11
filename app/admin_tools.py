from flask import request
from app import app

@app.route('/eval')
def run_eval():
    expr = request.args.get('expr', '1+1')
    # INSECURE: eval on user-provided input
    result = eval(expr)
    return str(result)