# -------------  Dockerfile --------------
FROM alpine
RUN apk update && apk add bash
ENV BASH /bin/bash
COPY log_write.sh log_write.sh
RUN chmod +x log_write.sh
RUN ls -al
ENTRYPOINT ./log_write.sh
