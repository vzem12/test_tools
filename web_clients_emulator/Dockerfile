# -------------  Dockerfile --------------
FROM alpine
RUN apk update && apk add bash && apk --no-cache add curl
ENV BASH /bin/bash
COPY request.sh request.sh
RUN chmod +x request.sh
ENTRYPOINT ./request.sh

