# app/admin_tools.py (SECURE)
import ast
from flask import request, jsonify
from app import app

@app.route('/eval')
def run_eval():
    """Safely evaluate Python literals only."""
    expr = request.args.get('expr', '1+1')
    
    try:
        #  SECURE: Only evaluates literals (numbers, strings, lists, dicts)
        # Rejects: function calls, imports, variables, operators
        result = ast.literal_eval(expr)
        return jsonify({"success": True, "result": result})
    except (ValueError, SyntaxError) as e:
        return jsonify({"success": False, "error": "Invalid expression"}), 400