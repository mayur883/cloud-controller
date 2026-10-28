"""
Main entry point for starting the Laboratory Cloud Controller server.
"""

import uvicorn
from cloud_controller.config import CONTROLLER_HOST, CONTROLLER_PORT

if __name__ == "__main__":
    print(f"===============================================================")
    print(f"Starting Laboratory Cloud Controller on http://{CONTROLLER_HOST}:{CONTROLLER_PORT}")
    print(f"Multi-Tenant Storage • Apache HDFS • AES-256-GCM • S3/GCS CDN")
    print(f"Web Dashboard: http://localhost:{CONTROLLER_PORT}")
    print(f"Swagger API Docs: http://localhost:{CONTROLLER_PORT}/docs")
    print(f"===============================================================")
    uvicorn.run("cloud_controller.api:app", host=CONTROLLER_HOST, port=CONTROLLER_PORT, reload=False)
