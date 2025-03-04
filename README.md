# OIDC Proxy to replace Keycloak for custom auth API

This project for OHIF Viewer that use keycloak as IAM.
I have custom auth API that can authteticated and authorized access to OHIF Viewer
This proxy replacing keycloak to use custom API

# Usage
1. Clone this repoitory
2. Modify the .env to your environment
3. Modify the OHIF Viewer config.js suitable for your environment
4. docker compose up --build
5. (Optional) Put Nginx in front of the proxy and use SSL to gain the https access
6. Open OHIF Viewer