#!/usr/bin/env python3
"""
Run Flask server with Eventlet support for Socket.IO
"""

import eventlet
import os
eventlet.monkey_patch()

from flask import jsonify
from app import app, socketio

# Add health check endpoint for deployment monitoring
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "service": "FinGuardAI Backend"
    })

if __name__ == '__main__':
    print("Starting FinGuardAI backend server with Eventlet...")
    # Use PORT environment variable if available (for cloud deployment)
    port = int(os.environ.get('PORT', 5001))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
