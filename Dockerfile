ARG PYTHON=2.7
FROM python:${PYTHON} AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update -y && \
    apt dist-upgrade -y && \
    apt install -y swig && \
    pip install --upgrade pip && \
    pip install build

WORKDIR /src
COPY . /src/

RUN make python && \
    make prepare_module && \
    cp README.md build/ && \
    python -m build build/

FROM python:${PYTHON}-slim

WORKDIR /app/
COPY --from=builder /src/build/dist/* /app/

RUN pip install --upgrade pip && \
    pip install l2tester*.whl

CMD [ "/usr/local/bin/shark" ]
