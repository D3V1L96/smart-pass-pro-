graph TD

Browser --> Frontend

Frontend --> ExpressAPI

ExpressAPI --> SocketIO

ExpressAPI --> JWT

ExpressAPI --> PostgreSQL

ExpressAPI --> Resend

ExpressAPI --> GoogleOAuth

PostgreSQL --> NeonCloud
