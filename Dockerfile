# Forge — a standalone GitHub-compatible git forge (pure Go, no git binary).
#
# Build stage: compile the static binary.
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go git.go ./
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o forge .

# Final stage: FROM scratch, only the static binary. No git, no shell, no OS.
FROM scratch
COPY --from=builder /app/forge /forge
ENV FORGE_DATA=/data PORT=8000
VOLUME ["/data"]
EXPOSE 8000
ENTRYPOINT ["/forge"]
